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

首先，iTunes与iPhone的库`MobileDevice`被逆向出私有API` __sendCommandToDevice`和`__sendFileToDevice`。

然后，Apple 并没有删除恢复模式中的很多命令，比如`cp`。

所以，流程大致如下：

- 让设备进入恢复模式，从固件中找出 Restore Ramdisk 和 kernelcache，然后上传到设备上。
- 创建两个文件 `/var/root/Media/fstab` 和 `/var/root/Media/Services.plist`，后者会创建一个新的服务`com.apple.afc2`，允许通过AFC访问所有文件目录。

其中，前者会被修改为

```
/dev/disk0s1 / hfs rw 0 1
/dev/disk0s2 /private/var hfs rw 0 2

```

而后者则会在现有基础上新增一项服务

```
	...
	<key>com.apple.afc2</key>
	<dict>
		<key>Label</key>
		<string>com.apple.afc2</string>
		<key>ProgramArguments</key>
		<array>
			<string>/usr/libexec/afcd</string>
			<string>--lockdown</string>
			<string>-d</string>
			<string>/</string>
		</array>
	</dict>
	...
```



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

完整代码可以在[这里](https://github.com/OpenJailbreak/JailbreakMe-1.0/blob/master/tiff_exploit.cpp)看到。

## 修复

- 更新`libtiff`库

# mknod-vulnerability 

**iOS 版本**：iOS 1.1.2

**利用软件**：OktoPrep + [touchFree](https://github.com/planetbeing/touchfree)

iOS 1.1.2 版本之后，Apple 修复了 `libtiff` 和 `iBoot cp-command` 的漏洞，然而，因为前文所提到的，iPhone 第一代可以随便刷机，所以新版的方法也很简单粗暴：先在 iOS 1.1.1 动手脚，然后升级到 iOS 1.1.2 继续搞事情。

具体来说：

- 在 iPhone 升级之前，OktoPrep 使用`mknod /var/root/Media/disk c 14 1`直接在用户盘符创建一个字符设备，这句命令的意思是，为主设备号是14，次设备号是1的设备创建一个在`/var/root/Media/disk`的字符设备，这等同于`/dev/rdisk0s1`。（可以使用`ls -lR /dev`查看主次设备号）
- 升级系统到 iOS 1.1.2，由于升级系统只更改fsroot，而我们创建的文件在用户数据分区中，所以不受影响。
- touchFree 检查 `/var/root/Media/disk` 是否存在，然后创建`/var/root/Media/touchFree`文件夹，复制必要文件到此文件夹中。
- 将`/var/root/Media/disk`dump为`rdisk0s1.dmg`，挂载这个dmg文件，修改`/etc/fstab`
- 往[`com.apple.syslogd.plist`](https://github.com/planetbeing/touchfree/blob/f01e306513fd01c678d6e639ac53692daf6b4383/java/resources/required/com.apple.syslogd.new.plist)里面添加`DYLD_INSERT_LIBRARIES:/var/root/Media/touchFree/planetbeing.dylib`环境变量键值对（熟悉逆向的朋友们可能已经猜到了，没错，syslogd在下一次执行的时候会首先被注入这个动态库。）
- 动态库会将touchFree文件夹里的东西复制到`/bin`，创建 AFC2 服务，运行`/var/root/Media/touchFree/run.sh`脚本，然后把自己的注入环境变量删掉。
- 脚本会继续复制`Installer.app`和ssh服务，然后给Springboard和lockdown打补丁。

其中，Springboard 补丁是因为当时 Springboard 显示的程序是写死在`allowedDisplayIcons`里的，所以需要给`[SBIconModel addItemsToIconList: fromPath: withTags:]`和` [SBIconController relayoutIcons]`里面打补丁，让`Installer.app`能显示在主屏幕，而lockdown的补丁主要是绕过iPhone激活锁。

## 修复:

- `/dev/rdisk0s1`被加上了`nodev`，所以不能再用`mknod`创建它的设备文件了。

# Ramdisk Hack

**iOS 版本**：<= iOS 1.1.5

**利用软件**：[ZiPhone](https://github.com/Zibri/ZiPhone/) & iLiberty

 从 iOS 1.1.3 开始，iPhone 新增了 `mobile`用户，大部分 app 都转为使用这个用户运行，这意味着即使出现像`libtiff`一样的 userland 漏洞，我们也不再能一招吃遍天了。

这次的漏洞则是出现在恢复模式中。虽然苹果把大部分debug命令都从 iBoot 中删除，但我们仍可以通过设定`nvram`中的`boot-args`参数来指定启动参数。如果指定挂载一个 Ramdisk，那么内核会在下次开机时自动挂载。尽管如此，如前面讲到的，在一般情况下，iBoot 会校验签名，而有人发现，如果指定 Ramdisk 文件的起始地址大于 0x09C00000 后，这个签名校验机制就失效了，这意味着没有签名的 Ramdisk 也可以被挂载。

整个步骤流程就变得简单起来：

- 上传所有资源到`/var/mobile/Media`（还记得Media文件夹吗？从这个版本开始它存在于`mobile`用户的文件夹里了）

- 把自制 Ramdisk 上传到设备上。

- 设置环境变量（上述两步，还是使用之前的私有API）

  ```bash
  setenv unlock 1
  setenv activate 1
  setenv jailbreak 1
  setenv boot-args rd=md0 -s -x pmd0=0x09CC2000.0x0133D000
  ```

- 发送`fsboot`和`bootx`，让设备从Ramdisk启动
- Ramdisk 还是做之前做的几件事：挂载fsboot为读写，安装`Installer.app`，多了一样解锁。

```bash
# System-wide .profile for sh(1)
PATH="/bin:/sbin:/usr/bin:/usr/local/bin:/usr/sbin"
export PATH
/bin/sleep 5
/bin/echo "Starting unlock..."
if [ "`/usr/bin/nvram -p|/bin/grep unlock1`" != "" ] ; then /zib/gunlock /zib/secpack /zib/ICE04.02.13_G.fls; fi
if [ "`/usr/bin/nvram -p|/bin/grep unlock2`" != "" ] ; then /zib/gunlock2 /zib/secpack /zib/ICE04.02.13_G.fls a12345
6789012345 ; fi
/sbin/fsck_hfs /dev/disk0s1
/sbin/fsck_hfs /dev/disk0s2
if [ "`/usr/bin/nvram -p|/bin/grep jailbreak`" != "" ] ; then
/bin/echo "Starting jailbreak..."
/sbin/mount_hfs -o noasync,sync /dev/disk0s1 /mnt1
/sbin/mount_hfs -o noasync,sync /dev/disk0s2 /mnt2
if [ -e /dev/rmd1 ]; then /bin/dd if=/dev/rmd1 of=/mnt2/root/mem_dump.bin bs=4096 count=4096; fi
#/zib/bbupdater -l /zib/BOOT03.09_M3S2.fls
#/bin/sleep 20
# jailbreak
# disk0s1
if [ "`/usr/bin/nvram -p|/bin/grep activate`" != "" ] ; then 
/bin/echo "Patching lockdownd..."
/bin/ipatcher -l /mnt1/usr/libexec/lockdownd
/bin/cp /zib/fstab /mnt1/private/etc/fstab
/usr/bin/unzip -o -K -X /zib/Installer.zip -d /mnt1/Applications/
#/usr/bin/unzip -o -K -X /zib/BSD_Subsystem.zip -d /mnt1/
#/usr/bin/unzip -o -K -X /zib/openssh-4.6p1-1.zip -d /mnt1/
# disk0s2
if [ "`/usr/bin/nvram -p|/bin/grep activate`" != "" ] ; then
/bin/echo "Activating youtube..."
/bin/mkdir -p /mnt2/private/var/root/Library/Lockdown
/bin/cp /zib/data_ark.plist /mnt2/root/Library/Lockdown/
/bin/cp /zib/device_private_key.pem /mnt2/root/Library/Lockdown/
/bin/cp /zib/device_public_key.pem /mnt2/root/Library/Lockdown/
/bin/mkdir -p /mnt2/mobile/Library/Installer/Temp
/bin/mkdir -p /mnt2/root/Library/Installer/Temp
/bin/cp /zib/LocalPackages.plist /mnt2/mobile/Library/Installer/ 
/bin/cp /zib/LocalPackages.plist /mnt2/root/Library/Installer/ 
#/bin/cp /zib/RemotePackages.plist /mnt2/mobile/Library/Installer/ 
#/bin/cp /zib/RemotePackages.plist /mnt2/root/Library/Installer/ 
/bin/cp /zib/PackageSources.plist /mnt2/mobile/Library/Installer/ 
/bin/cp /zib/PackageSources.plist /mnt2/root/Library/Installer/ 
/bin/cp /zib/TrustedSources.plist /mnt2/mobile/Library/Installer/ 
/bin/cp /zib/TrustedSources.plist /mnt2/root/Library/Installer/
/bin/cp /zib/com.apptapp.Installer.plist /mnt2/mobile/Library/Preferences/
/bin/cp /zib/com.apptapp.Installer.plist /mnt2/root/Library/Preferences/
#end jailbreak
/bin/echo "Unmounting filesystems..."
/usr/bin/umount /mnt1
/usr/bin/umount /mnt2
/sbin/fsck_hfs /dev/disk0s1
/sbin/fsck_hfs /dev/disk0s2
/usr/bin/nvram auto-boot=true
/usr/bin/nvram boot-args=""
/usr/bin/nvram -d unlock1
/usr/bin/nvram -d unlock2
/usr/bin/nvram -d jailbreak
/usr/bin/nvram -d activate
#/usr/bin/nvram -d unlock2
/bin/echo "Now rebooting..."
/sbin/reboot
while (true); do sleep 1; done
```

- 重启之后，它还会给 Springboard 打上补丁。

## 修复

- `boot-args`从iOS 2.0开始，在生产环境中不生效。（这一点可以从 iBoot 泄露的源码中看出）

  ```c
  // iBoot/apps/iBoot/main.c
  bool
  env_blacklist_nvram(const char *name)
  {
      static const char * const whitelist[] = {
          ...
  #if DEVELOPMENT_BUILD || DEBUG_BUILD
          "boot-args", // factory needs to set boot-args
  #endif
          ...
          NULL
      }
      ...
  }
  ```

# 总结

本文回顾了 iOS 1 中大部分已经公开并使用的越狱工具与他们的利用方法，以及苹果的修补方法。

虽然 iOS 1 离我们已经有一轮年头了，但从上面的做的事情中，我们可以看出，实际上，越狱所做的东西还是没有变化太多。

就以本文所有越狱工具为例，基本上就做这么几件事:

- 修改 `/etc/fstab`，挂载系统盘为`rw`
- 安装一个软件包管理器(`Installer.app`)，然后安装第三方软件
- 给系统打补丁（解锁，换铃声，新增AFC2服务）

为了做这些事情，我们需要:

- 修改系统文件
- 获取系统最高权限

在之后长达 12 年中，围绕着这两件事情，苹果跟安全研究员们展开了斗智斗勇，实际上，现代所有越狱工具也都或多或少地实现了上面所有的事，只不过，要绕过的安全机制多了许多。



# 参考资料

[1] https://www.peerlyst.com/posts/ios-jailbreaks-history-part-1-ivan-ponurovskiy?trk=profile_page_overview_panel_posts

[2] https://www.theiphonewiki.com/

[3] http://blog.iphone-dev.org/