---
title: "ThinkBook 触控板冷启动失效故障修复记录 (DSDT ACPI Override)"
date: 2026-08-25T05:08:06+08:00
draft: false
tags: ["Arch Linux", "ACPI", "DSDT", "ThinkBook", "Kernel"]
categories: ["Linux", "Hardware"]
---

# ThinkBook 触控板冷启动失效故障修复记录 (DSDT ACPI Override)

## 1. 故障现象与根本原因

### 现象描述
ThinkBook 笔记本在 Linux（Arch Linux / Wayland 环境）下出现触控板（Cirque / I2C HID）冷启动（断电开机）无法识别的故障，但在热重启（Warm Reboot）或者长按电源键 10s+ 强制冷重启的方式下能恢复。

### 根本原因 (Root Cause)
联想 BIOS 固件自带的 ACPI DSDT 表存在代码缺陷。
在触控板的资源配置方法（`\_SB.PC00.I2C0.TPAD._CRS`）中，定义了一个长度为 `0x05` 的数据包（`Package`），但在执行逻辑中尝试通过 `Index (0x5)` 访问第 6 个元素（索引从 0 开始），触发了数组越界。

* **Windows 表现：** 容错机制忽略了越界，触控板可勉强初始化。
* **Linux 表现：** 内核严谨拦截并抛出 `AE_AML_PACKAGE_LIMIT` 严重异常，中止执行 `_CRS` 方法，导致触控板在冷启动缺少电源/引脚资源分配时直接“失联”。

```text
ACPI BIOS Error (bug): AE_AML_PACKAGE_LIMIT, Index (0x000000005) is beyond end of object (length 0x5)
ACPI Error: Aborting method \_SB.PC00.I2C0.TPAD._CRS due to previous error (AE_AML_PACKAGE_LIMIT)

```

---

## 2. 修复方案：DSDT 内存热重载 (ACPI Override)

通过在 Linux 内核启动的极早期（Early CPIO 阶段）向内核注入修正后的 `DSDT` 表，覆盖主板 BIOS 的错误配置，无需刷写实体 BIOS。

### 步骤一：提取并反编译 DSDT

```bash
mkdir -p ~/acpi_fix && cd ~/acpi_fix

# 提取主板原生 ACPI 二进制表
sudo acpidump > acpidump.bin
acpixtract -a acpidump.bin

# 反编译 DSDT 为人类可读的 ASL 源码
iasl -e ssdt*.dat -d dsdt.dat

```

---

### 步骤二：源码修复 (dsdt.dsl)

打开 `dsdt.dsl` 进行以下修正：

1. **修复触控板数组越界（核心修复）：**
定位到 `Device (TPAD)` 下的 `Method (_CRS)` 相关配置，找到被引用的 Package 定义，将其容量由 `0x05` 扩容至 `0x06`：
```asl
// 修改前
Name (TPID, Package (0x05) { ... })

// 修改后
Name (TPID, Package (0x06) { ... })

```


2. **清理无用的悬空外部声明与调用（编译错误修复）：**
反编译器生成的外部声明会引发编译报错，需注释或删除：
* 注释掉文件开头的 `PS0X` 与 `PS3X` 外部声明（我的电脑有四个）：
```asl
// External (_SB_.PC00.XHCI._PS0.PS0X, MethodObj)
// External (_SB_.PC00.XHCI._PS3.PS3X, MethodObj)
// External (_SB_.PC02.XHCI._PS0.PS0X, MethodObj)
// External (_SB_.PC02.XHCI._PS3.PS3X, MethodObj)

```


* 注释掉对应 XHCI 方法体内部对上述空函数的调用：
```asl
// PS0X ()
// PS3X ()

```





---

### 步骤三：编译并打包为 Early CPIO

```bash
# 1. 重新编译生成二进制 AML 文件（确保 0 Errors）
iasl -sa dsdt.dsl

# 2. 备份编译产物
sudo cp dsdt.aml /boot/acpi_override.aml

# 3. 按照内核规范路径打包为未压缩的 CPIO 归档
mkdir -p /tmp/acpi_fix/kernel/firmware/acpi
sudo cp /boot/acpi_override.aml /tmp/acpi_fix/kernel/firmware/acpi/dsdt.aml
cd /tmp/acpi_fix
sudo find kernel | sudo cpio -H newc -o | sudo tee /boot/acpi_override.cpio > /dev/null

# 验证 CPIO 包内路径结构（必须严格匹配 4 层路径）
sudo cat /boot/acpi_override.cpio | cpio -it

```

---

### 步骤四：集成至 Unified Kernel Image (UKI / systemd-boot)

由于 Arch Linux 采用 UKI（`arch-linux.efi`）模式，且新版 `mkinitcpio` 废弃了 `--microcode` 选项，最稳定标准的方案是**利用微码拼接（CPIO Concatenation）**。

```bash
# 1. 备份原英特尔微码
sudo cp /boot/intel-ucode.img /boot/intel-ucode.img.bak

# 2. 将 ACPI CPIO 补丁缝合进微码镜像末尾
sudo sh -c 'cat /boot/intel-ucode.img.bak /boot/acpi_override.cpio > /boot/intel-ucode.img'

# 3. 重新生成 UKI 启动镜像
sudo mkinitcpio -P

```

---

## 3. 持久化防护：防止微码更新覆盖 (Pacman Hook)

当系统执行 `pacman -Syu` 更新 `intel-ucode` 时，新文件会覆盖已拼接的补丁。通过编写 Pacman Hook，使其在微码更新后、UKI 重打包前自动执行缝合。

新建文件 `/etc/pacman.d/hooks/89-acpi-override.hook`：

```ini
[Trigger]
Operation = Install
Operation = Upgrade
Type = Package
Target = intel-ucode

[Action]
Description = Patching intel-ucode with custom ThinkBook DSDT ACPI override...
When = PostTransaction
Exec = /bin/sh -c 'cp /boot/intel-ucode.img /boot/intel-ucode.img.bak && cat /boot/intel-ucode.img.bak /boot/acpi_override.cpio > /boot/intel-ucode.img'

```

> **注：** Hook 命名为 `89-*` 是为了保证其执行优先级高于 `90-mkinitcpio.hook`，确保内核打包时微码已缝合完成。

---

## 4. 验证与诊断命令

1. **验证 Pacman Hook 运作：**
```bash
sudo pacman -S intel-ucode

```


2. **验证冷启动后补丁生效（核心判据）：**
执行彻底关机（`poweroff`），冷启动开机后运行：
```bash
sudo journalctl -k -b 0 | grep -iE "AE_AML_PACKAGE_LIMIT|I2C0.TPAD"

```


* **输出为空**：表示 DSDT 越界错误已彻底被重载表修复，触控板在冷启动正常分配资源并唤醒。


