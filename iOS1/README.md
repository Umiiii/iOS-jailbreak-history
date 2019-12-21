---
title: "iOS 越狱史及技术简析 - iPhone OS (iOS 1)"
date: 2019-12-13T13:27:59+08:00
draft: false
tags: ["iPhone","jailbreak"]
layout: post
---

当时，iOS 还被叫做 iPhone OS ，预装在 iPhone 第一代里面（为了方便起见，下文我们还是叫它 iOS）。

iOS 1.0 的原装固件 iPhone1,1_1.0_1A543a_Restore.ipsw 只有 91.18 MB，这就注定了它里面不会有太多功能。没有 App Store，一个屏幕就装下了所有的app，SpringBoard 直接写死所有 app 的名称。

![iOS 1](https://upload.wikimedia.org/wikipedia/en/8/8a/IPhone_OS_1_screenshot.jpg)

苹果一开始的想法是，用户只需要使用 Safari 访问一切他们所需要的应用，不仅如此，系统连铃声也无法自己更换，再加上一开始只有跟美国运营商at&t签订合约，才可以购买 iPhone，即便你签完合约之后，你的 iPhone 也不能使用其他运营商的 sim 卡，所以这个时候 iPhone 黑客们要做的事情很简单，取得系统最高权限，然后在这个基础上：

- 逆向原生 app，搞懂 app 是如何工作的，然后提供一套工具链，让大家开发自制的第三方应用（事实证明，在之后的 iOS 2.0 中，苹果公布的 iPhone SDK 就是这样一套东西）
详细可以查看《iPhone Open Application Development》一书
- 提供一个便捷的方式供用户安装第三方应用
- 解锁 iPhone，让用户能使用其他运营商 ———— 也被称为 Hacktivation

最初版本(iOS 1.0)下， iPhone 具有的保护机制如下：

| 名称              | 简介                                                         |
| ----------------- | ------------------------------------------------------------ |
| Secure Boot Chain | iPhone 启动时，会校验每个引导阶段的签名，若不通过，则无法进行下一阶段的引导 |
| fsroot 只读       | iOS 系统盘符与用户数据盘符分离，前者会被挂载为只读           |
| AFC Restriction   | iPhone 与电脑通信时，管理通信的AFC(Apple File Conduit)服务默认只允许访问`/Media`文件夹 |
| lockdown          | 管理运营商激活锁                                             |

所有应用程序都放在`/Application`下，并默认以`root`权限执行，没有代码签名，甚至刷机不会校验 SHSH，这意味着你可以随便降级，所以在这个阶段，越狱实际上是非常简单的。

# iBoot cp-command

**iOS 版本**: iOS 1.0 - iOS 1.0.2 

**利用软件**: iBrickr (Windows) / AppTapp Installer (Mac OS X)

严格意义上来说，这并不算一个漏洞，而更像是一个 feature。

起因是 Apple 并没有删除恢复模式中的很多命令，比如`cp`。

流程大致如下：
- 让设备进入恢复模式，从固件中找出 Restore Ramdisk 和 kernelcache，然后上传到设备上。
- 创建两个文件 `/var/root/Media/fstab` 和 `/var/root/Media/Services.plist`，后者会创建一个新的服务`com.apple.afc2`，允许通过AFC访问所有文件目录。
- 将 `/dev/disk0s1` 挂载到 `/mnt1`，用户数据`/dev/disk0s2`挂载到`/mnt2`，然后把我们上一步创建的两个文件用`cp`分别替换掉`/mnt1/etc/fstab`和`/mnt1/System/Library/Lockdown/Services.plist`
- 重启之后电脑就可以访问完整的系统盘了。iBrickr 还会安装 PXLDaemon 守护进程，这个守护进程可以与电脑端 iBrickr 通信，安装第三方软件包，替换铃声等等。而 AppTapp Install 则会安装 `Installer.app`，其功能与前者大致相同。

## 修复

- 在 iOS 1.0.2 后更新 iBoot，删除了`cp`以及其他一些内部命令。

# libtiff-exploit (CVE-2006-3459)

**iOS 版本**: iOS 1.0 - iOS 1.1.1

**利用软件**: AppSnapp / JailbreakMe 1.0

核心原理是经典的 buffer overflow --- `libtiff` 在处理 tiff 文件的时候会发生 buffer overflow，允许任意代码执行，只需要让用户访问一个含有tiff图片的网站就可以完成越狱。

碰巧的是，当年 PSP 也饱受 tiff 漏洞的[摧残](https://www.youtube.com/watch?v=WRWJtI-HzpY)，这个漏洞应该是从 PSP 的破解中收到了启发。

shellcode 做了一些微小的工作:
- 将`/var/root/Media`重命名为`/var/root/oldMedia`
- 创建符号链接`/var/root/Media/ -> /`
- 重新挂载`/dev/disk0s1`为读写

```c
    stack.Add(Node(0, Node::PTR));           // r0 = "/var/root/Media"
    stack.Add(Node(1, Node::PTR));           // r1 = "/var/root/Oldmedia"
    stack.Add(Node(20, Node::BYTES));        // r2,r3,r5,r6,r12
    stack.Add(Node(12, Node::STACK));        // sp    -> offset 12
    stack.Add(ldmia_sp_r4);                  // lr = load r4,r7,pc from sp
    stack.Add(rename);                       // pc = rename(r0, r1)

    ...

    stack.Add(Node(2, Node::PTR));           // r0 = "/"
    stack.Add(Node(0, Node::PTR));           // r1 = "/var/root/Media"
    stack.Add(Node(20, Node::BYTES));        // r2,r3,r5,r6,r12
    stack.Add(Node(12, Node::STACK));        // sp -> offset 12
    stack.Add(ldmia_sp_r0);                  // lr = load from r0..pc from sp
    stack.Add(symlink);                      // pc = symlink(r0, r1)

    stack.Add(Node(3, Node::PTR));           // r0 = "hfs"
    stack.Add(Node(2, Node::PTR));           // r1 = "/"
    stack.Add(Node(0x00050000, Node::VAL));  // r2 = MNT_RELOAD | MNT_UPDATE
    stack.Add(Node(8, Node::STACK));         // r3 = **data
    stack.Add(mount);                        // pc = mount(r0, r1, r2, r3)
    stack.Add(Node(4, Node::PTR));           // data = "/dev/disk0s1"
```

之后，所有操作方法跟上面一样，新增 afc2 服务

完整代码在[这里](https://github.com/OpenJailbreak/JailbreakMe-1.0/blob/124614114d9a9336db5d37e815896c598a86c06b/tiff_exploit.cpp#L176)。

## 修复

- 更新`libtiff`库