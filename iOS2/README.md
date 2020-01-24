---
title: "iOS 越狱史及技术简析 - iOS 2"
date: 2019-12-30T18:02:59+08:00
draft: false
tags: ["iPhone","jailbreak"]
layout: post

---
# 前言

在整理这篇文章的时候，我一直在犹豫要不要写上这个版本更新的安全机制，因为实际上真正的越狱利用部分与他们并没有关系，而因为是刚刚加入系统中，后续对他们的收尾工作并不复杂，但思索再三，还是将他们写下来了，原因无他：只有一步一步追溯苹果的更新脚步，才能理解在后续版本中他们做的安全措施。


# 回顾

在上一篇文章中，我们已经提到了苹果对 iOS 1 的安全保护正在一步一步进化中。截止 iOS 1.1.5，从上至下层级排列，iOS 的安全措施如下

| 名称            | 出现版本  | 说明                                                         |
| --------------- | --------- | ------------------------------------------------------------ |
| Secure Boot     | iOS 1.0   | 启动链的每个环节都会负责验证下一阶段的签名                   |
| fsroot 只读     | iOS 1.0   | 系统盘 /dev/disk0s1 默认是只读的                             |
| AFC Restriction | iOS 1.0   | iPhone 通过 AFC 服务与电脑进行数据交换，这个服务默认只允许宿主机访问`/Media`目录 |
| 固件加密        | iOS 1.1   | `IMG2`格式的系统固件通过`Key 0x837`被加密                    |
| mobile 用户     | iOS 1.1.3 | 在此之前，所用应用程序均使用`root`权限运行                   |

应该说，这个阶段的越狱并没有什么难度。越狱社区正处于萌芽状态，尽管并没有原生的中文支持，威锋社区已经通过修改内核文件的方法让 iPhone 成功支持了中文输入法与中文短信的显示。

随后，2008 年 7 月 1 日， 苹果推出了 iOS 2 更新，同时公布了 iPhone 3G。 iOS 2 预装在 iPhone 3G 上，iPhone 1代也可以升级到 iOS 2。

# 代码签名与沙盒

这次更新之后，App Store 开始内置在 iPhone 内，这意味着用户可以自己下载并安装应用程序了。相对应的，iOS 新增了以下安全机制:

- 强制代码签名
  - 所有可执行程序、库、甚至内存中的代码，都必须经过苹果签名才能运行
- 应用程序沙盒
  - 应用程序默认情况下运行在沙盒中，限制其所能访问的资源(包括但不限于系统调用，文件等)

上述两个安全机制都被注册到 TrustedBSD 中的 Mandatory Access Control 扩展（MACF）里。TrustedBSD 是一个内核扩展程序的集合，从 Mac OS X 10.5（2007 年 10 月 26 日发布）开始，苹果将整个 TrustedBSD 都移植到了 XNU 内核中，所以 Mac OS X 和 iOS 也自然拥有了 MACF。

MACF 的架构大致如下:

```
    ^
    |
    |
 User Space
+------------------------------------------------------------+
|Ker|nel Space                                               |
|   |     +----------+            +-----------------------+  |
|   |     |          |            |                       |  |
|   |     |  MACF    |------------>     +-----------+     |  |
|   v     |          |            |     |  Policy 1 |     |  |
|         +----------+            |     +----+------+     |  |
|    Kernel   |  Access Event     |          |            |  |
|             v                   |          v            |  |
|    +--------+---------------+   |     +----+------+     |  |
|    |  Kernel Implmentation  |   |     |  Policy 2 |     |  |
|    +------------------------+   |     +----+------+     |  |
|    |    Kernel Object       |   |          |            |  |
|    +------------------------+   |          |            |  |
|             |                   |          |            |  |
|             |                   |          |            |  |
|    +--------v---------------+   |     +----v------+     |  |
|    |  File System, Network  |   |     |  Policy N |     |  |
|    +------------------------+   |     +-----------+     |  |
|                                 |                       |  |
|                                 +-----------------------+  |
|                                                            |
+------------------------------------------------------------+
```
安全策略可以编译时静态链接到内核，也可以在引导时加载，甚至在运行时动态加载。在主体访问客体时，MACF 会调用所有的安全策略，只有当所有的安全策略均表示同意，MACF 才会授权这次访问。

```
    +--------------------+      +-------------------+
    | User mode process  |      |  User Mode Daemon |
    +---------|-^--------+      +---------^---------+
+-------------|-|--------------------------------------------------+
              | |                         |
    +---------v-+--------+                |
    | sysent/mach_trap_tb|                |
    +---------|-^--------+           +----+---+
              | |                    | Policy |
    +---------v-+--------+     +----->        |
    |  syscall/trap #n   |     |     | Module |
    +---------|-^--------+     |     +--------+
              | |              |
    +---------v-+--------+     |
    |     M  A  C  F     ｜-----
    +--------------------+

```
在具体实现中，每次 MACF 均会检查是否有策略 hook 了 sycall/mach trap，如果是，那么就会拉起这个策略，由该策略判断允许还是阻止继续执行。

## 代码签名 (AppleMobileFileIntegrity)

从上述 MACF 架构中我们知道，要想在 iOS 实现代码签名机制，就需要自己提供一个验证代码签名的策略，然后注册相关 hook，这个工作由`AppleMobileFileIntegrity.kext`完成。它既不防止权限提升也不阻止未授权访问资源，它的工作仅限于保证文件的完整性(Integrity)和认证性(Authentication)。

由于代码签名验证的逻辑非常复杂，一般情况下不适合在内核态运行，所以 AMFI 由两部分组成，用户态的daemon - `/usr/libexec/amfid` 和内核态的`AppleMobileFileIntegrity.kext`组成。后者会在内核一初始化完成就注册到 MACF 的策略，如果初始化注册时出错，就会导致 kernel panic。而在初始化完成后想 unload 这个 kext，则会报错 -- "Cannot unload AMFI - policy is not dynamic"，然后接着给你来个 panic。与之相反，前者可以说是 AMFI 的阿克琉斯之踵，几乎在之后版本的所有越狱中都会拿这个下手绕过代码签名。

## 沙盒

与 AMFI 相同，沙盒也由一个用户态`/usr/libexec/sandboxd`和一个kext`Sandbox.kext`组成。在初始版本中(Sandbox<=165, iOS 1 ~ iOS 4)，沙盒机制是黑名单制的，这就意味着这个机制很容易被通过“白加黑”的手段绕过。所以苹果在 iOS 5 的时候重做了这个机制，重命名为"App Sandbox"，引入了容器(Container)的概念。

# 正文

## Pwnage

** 设备版本 ** : iPhone, iPod Touch, iPhone 3G (全版本)
** 利用软件 ** : Pwnage Tool, QuickPwn, WinPwn

第一个 bootrom 级别的漏洞。

首先，让我们回顾一下当时 iPhone 的两条启动链：
- 正常启动，bootrom 检查 LLB 签名并加载 LLB， LLB 检查 iBoot 签名并加载 iBoot， iBoot 检查内核签名并加载设备树和内核，内核完成最后的启动。
- DFU 模式下，bootrom 验证 WTF 的签名并加载 WTF (What's The Firmware)，WTF 加载 iBSS 签名并读取 iBSS，iBSS 加载设备树、 ramdisk 和内核，验证内核签名。

看起来很美，问题出在哪呢？让我们一条一条梳理：

- 在 iOS 1 时代，所有系统关键文件（如iBoot/iBEC/iBSS）都被用8900格式进行打包，里面含有*签名*与文件本身的 img2 数据。从 iOS 2 开始，苹果不再采用 8900 格式，但 WTF 映像文件除外
- 早期设备中，系统与用户文件储存在 NAND ，引导相关文件存放在 NOR 
- 将文件写入 NOR 需要通过 ramdisk 中的 `AppleImage3NORAccess.kext`，这个 kext 需要验证文件的签名

因为第三点，苹果认为没必要去验证 NOR 中文件的签名，因为他们已经被 kext 所代劳了，所以 bootrom 在正常启动时不会验证 LLB 的签名，然而，bootrom 还是会验证 WTF 的签名。由于 WTF 仍是 8900 格式，pwnage 通过构造特定的 8900 签名，导致 bootrom 在签名验证时栈溢出，从而永远返回验证成功来绕过 bootrom 的签名验证。接下来的步骤，由于可信启动链的破坏，就比较简单了。

首先，构造一个固件文件：
- 修改 WTF 签名，并将 WTF 中对下一阶段的签名验证关闭
- 修改 iBSS，iBEC， iBoot， LLB，关闭所有签名验证
- 关闭 ramdisk 中文件完整性校验，修改fstab
- 关闭代码签名(AMFI.kext)，关闭`AppleImage3NORAccess.kext`的代码签名验证
- 给设备树打补丁，让 `AppleImage3NORAccess.kext` 能获取到 Key 0x837，并用这个 Key 加密文件并写入 NOR 中

最后模拟 iTunes 让 iPhone 进入 DFU 模式后加载自制 WTF 文件就可以完成后续操作了，由于大同小异（增加afc2，安装包管理软件等），这里不再赘述。

值得注意的两点是：第一，Cydia.app 和 Installer.app 一起，在这里被正式加入越狱预装应用的行列；第二，没有找到有关绕过沙盒的资料，所以猜想这个机制应该一越狱就被关掉了，而且没有保护机制。

## ARM7 Go

** 设备版本 ** : iPod Touch 2
** 利用软件 ** : QuickPwn, RedSn0w Lite

iBoot 级别的漏洞。苹果在 iPod Touch 2 的第一个 iBoot 的版本里忘记把调试代码删了，留下了`arm7_go`和`arm7_stop`，前者可以从任意地址执行未签名代码。

于是我们还是照葫芦画瓢，DIY 固件文件：
- 修改 WTF 签名，并将 WTF 中对下一阶段的签名验证关闭
- 修改 iBSS，iBEC， LLB，关闭所有签名验证
- 修改 fsroot 的 fstab 和 Services.plist，新增afc2，把 cydia 加进去
- 对于 iBoot：第一步，关闭签名验证。 第二，在上一篇文章中我们已经提到，iBoot 在更新后不再处理大部分`boot-args`，除非设备处于调试模式，所以我们要把判断调试模式的语句打个补丁，让更多的flag可用。处理器内部有一个安全机制保证只有一部分内存段才能执行指令，所以最后一步是移除掉可执行指令内存的限制。

之后，等到设备进入 DFU 模式，RedSn0w Lite 会向设备发送最重要的一段命令:
```
arm7_stop
mw 0x9000000 0xe59f3014
mw 0x9000004 0xe3a02a02
mw 0x9000008 0xe1c320b0
mw 0x900000c 0xe3e02000
mw 0x9000010 0xe2833c9d
mw 0x9000014 0xe58326c0
mw 0x9000018 0xeafffffe
mw 0x900001c 0x2200f300
arm7_go
arm7_stop
```
mw $1,$2 会将 $2 写入到 $1 所在的地址中，反汇编，我们得到这样一小段指令
```
asm 
; e5 9f 30 14 e3 a0 2a 02 e1 c3 20 b0 e3 e0 20 00 e2 83 3c 9d e5 83 26 c0 ea ff ff fe 22 00 f3 00 
; Segment type: Pure code 
                    AREA ROM, CODE, READWRITE, ALIGN=0 
                    ; ORG 0x9000000 
                    CODE32 
                    LDR R3, =0x2200F300 
                    MOV R2, #0x2000 
                    STRH R2, [R3] 
                    MOV R2, #0xFFFFFFFF 
                    ADD R3, R3, #0x9D00 
                    STR R2, [R3,#0x6C0] 
loc_9000018 ; CODE XREF: ROM:loc_9000018 
                    B loc_9000018 
; --------------------------------------------------------------------------- 
dword_900001C DCD 0x2200F300 ; DATA XREF: ROM:09000000 
; ROM ends 
END
```
这段代码做了一点微小的工作：首先，将 0x2000 写入 `0x2200F300`，关闭签名检测；其次，将 `0xFFFFFFFF` 写入 `0x220196C0`，这个地方是flag的值。如果flag=-1，那么 iBoot 会认为设备处于调试模式，关闭所有其他的限制。

之后，我们将事先准备好的固件文件一个一个发送过去，然后，设置`boot-path`，从我们准备好的内核直接启动！
```
bat

echo "[xx] Sending patched iBSS 2.2.1..."
sudo ./iRecovery -f ${files}/iBSS221pwn.dfu 
echo "[xx] Go into recovery mode..."
sudo ./iRecovery -s << EOF
go
/exit
EOF

# REPLUG HERE?
## echo PLEASE UNPLUG/REPLUG THE IPOD
## read A
sleep 5

echo "[xx] Sending semi-tethered iBoot 2.2.1.."
sudo ./iRecovery -f ${files}/iBoot221semi.img3

echo "[xx] Go into recovery mode..."
sudo ./iRecovery -s << EOF
go
/exit
EOF

sleep 5
echo "[xx] Configuring environment"
sudo ./iRecovery -s << EOF
setenv boot-path /System/Library/Caches/com.apple.kernelcaches/kernelcache.s5l8720p
fsboot
/exit
EOF

sleep 5
echo "[xx] Here we go!"
sudo ./iRecovery -s << EOF
go
/exit
EOF
```

需要注意的一点是，由于我们修改了 iBoot 文件，在重启之后 bootrom 会校验 iBoot 签名，显然这会导致失败，回落到 DFU。所以每次我们重启设备，都需要插上电脑继续进行引导。

# 总结

至此，我们已经看完了 iOS 2 时代所有的漏洞利用和更新的安全机制。两位门神 AMFI 和 Sandbox 的加入也开始让 iOS 的安全走上了正轨，我们所耳熟能详的 Cydia 作者 Saurik 已经发布了这个灰色小盒子的第一个版本，获得了社区的认可。此时 AMFI 和 Sandbox 还非常地脆弱，可以看到，工具甚至都没有直接利用他们的漏洞，这时候苹果还并不知道，之后 iOS 会成长成什么样的庞然大物。

应该说，只有第一个漏洞是正常开拓了一个新的时代的。由此，越狱社区开始重视 iOS 的 bootrom 相关安全研究。

# 后记

这篇东西说长也不算长，但坑了很久，一个原因是因为 Dota 太好玩了，另外一个原因是由于笔者水平不足，难免需要多查一些资料保证准确性，同时也在思考文章的架构需要怎么写才能更合理。如果你有什么意见，欢迎向我提出。