```bash      
 ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗      ██████╗  ██████╗ ██╗  ██╗
 ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║      ██╔══██╗██╔═══██╗╚██╗██╔╝
 ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║█████╗██████╔╝██║   ██║ ╚███╔╝ 
 ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║╚════╝██╔══██╗██║   ██║ ██╔██╗ 
 ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝      ██████╔╝╚██████╔╝██╔╝ ██╗
 ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝       ╚═════╝  ╚═════╝ ╚═╝  ╚═╝
      
                Lightweight Hypervisor-Based Kernel Protector
```

# 1. Notice
# 1.1. Presentations and Papers
Shadow-box is a lightweight and practical kernel protector, and it was introduced at [Black Hat Asia 2017](https://www.blackhat.com/asia-17/briefings.html#myth-and-truth-about-hypervisor-based-kernel-protector-the-reason-why-you-need-shadow-box), [Black Hat Asia Arsenal 2017](https://www.blackhat.com/asia-17/arsenal.html#shadow-box-lightweight-hypervisor-based-kernel-protector), and [HITBSecConf 2017](http://conference.hitb.org/hitbsecconf2017ams/sessions/shadowbox-the-practical-and-omnipotent-sandbox/).

You can see the demo videos at [Demo 1](https://youtu.be/3_cFDVHWCXA) and [Demo 2](https://youtu.be/s7iZYg4vP4E). [Demo 1](https://youtu.be/3_cFDVHWCXA) shows that if you use only kernel-level protection mechanism such as page write-protect, rootkits can neutralize it. [Demo 2](https://youtu.be/s7iZYg4vP4E) shows that if you use kernel-level protection mechanism with Shadow-box, then rootkits cannot neutralize it and cannot work. 

# 1.2. Contributions
We always welcome your contributions. Issue report, bug fix, new feature implementation, anything is alright. Feel free to send us. 

# 2. Introduction of Shadow-Box
Shadow-box is a security monitoring framework for operating systems using state-of-the-art virtualization technologies. 
Shadow-box has a novel architecture inspired by a shadow play. We made Shadow-box from scratch, and it is primarily composed of a lightweight hypervisor and a security monitor. 

The lightweight hypervisor, Light-box, efficiently isolates an OS inside a guest machine, and projects static and dynamic kernel objects of the guest into the host machine so that our security monitor in the host can investigate the projected images. 
The security monitor, Shadow-Watcher, places event monitors on static kernel elements and tests security of dynamic kernel elements. 

Shadow-box manipulates address translations from the guest physical address to the host physical address in order to exclude unauthorized accesses to the host and the hypervisor spaces. In that way, Shadow-box can properly introspect the guest operating system and mediate all accesses, even when the operating system is compromised.

# 3. How to Build 
# 3.1. Prepare Kernel Build Environment (Ubuntu 16.04)
Because the Shadow-box protects the code area of kernel, it conflicts with the runtime kernel patch feature (CONFIG_JUMP_LABEL). Therefore, if your kernel uses the runtime kernel patch feature, you should remove the feature. To remove it, you need to set a kernel build environment, change the kernel options, and install. The process is as follows.

```bash
# Prepare kernel source and build environment
$> apt-get source linux
$> sudo apt-get build-dep linux
$> sudo apt-get install ncurses-dev

# Make new .config file
$> cd linux-<your_kernel_version>
$> cp /boot/config-<your_kernel_version> .config
$> make menuconfig
# Load the .config file using the "Load" menu and save it to .config using the "Save" menu.

$> sed -i 's/CONFIG_JUMP_LABEL=y/# CONFIG_JUMP_LABEL is not set/g' .config

# Build kernel and modules
$> make -j8; make modules

# Install kernel and modules
$> sudo make modules_install
$> sudo make install
``` 

# 3.2. Prepare Kernel Symbols
Shadow-box should locate the data structures and functions for kernel integrity verification. These symbols can be found using kallsyms, but all symbols are not exposed to kallsyms. Therefore, Shadow-box uses the System.map file to embed symbols and kernel versions.
How to add symbols and kernel versions to Shadow-box is as follows:

```bash
$> uname -v
#37-Ubuntu SMP Mon Apr 18 18:33:37 UTC 2016			<== Kernel version

# Copy system.map file to kernel_version name
$> cp /boot/System.map-<your_kernel_version> system.map/"#37-Ubuntu SMP Mon Apr 18 18:33:37 UTC 2016.map"
```

# 3.3. Build Shadow-Box
When the kernel symbol is ready, type "make" command to build the Shadow-box. Then you can find shadow_box.ko in the same directory.
```bash
$> make
$> ls
shadow_box.ko shadow_box.h ...

```

# 4. How to Use
Shadow-box is loadable kernel module (LKM). So, when you need protection, you can load the shadow-box.ko module into the kernel with the insmod command.
```bash
$> sudo insmod shadow-box.ko
```

# = Caution =
Shadow-box protects kernel code, read-only data, system table, privilege register, etc. from rootkits. So, if you want to use Shadow-box, you should disable some features below.
 * Disable CONFIG_JUMP_LABEL
   * Change kernel config (.config)
 * Disable hibernation and suspend
   * Change system power management setting
 * Disable irqbalance service if you want to enable IOMMU feature of Shadow-box
   * Use "sudo update-rc.d irqbalance disable" command



