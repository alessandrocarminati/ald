# ALD
Since the Linux 5.4 when the lockdown LSM has been implemented, the current linux 5.9.1 has not yet implemented any option to lift kernel lockdown status.
The `SysReq+x` mentioned on the `man kernel_lockdown.7`, is still not yet been integrated with the main branch.
More info, please check [my blog](http://carminatialessandro.blogspot.com/2020/10/kernel-lockdown.html).

The following is my proposition to lift the kernel lockdown.

# Typical Scenario
Loading unsigned module is the typical operation lockdown denies.
```
$ sudo insmod ald.ko
insmod: ERROR: could not insert module ald.ko: Operation not permitted
```
If you find in the kernel logs something like the followings `Lockdown: insmod: unsigned module loading is restricted; see man kernel_lockdown.7`, you have no alternatives but sign the kernel module with a valid key.
The key used to build the kernel tree is not commonly available, in particular, if the kernel comes from a Linux distribution.
The only alternative to this is by using MOK ("Machine Owner Key").
Here a brief walk-through for signing a kernel module with a freshly registered MOK.
```
#find a suitable location in your filesystem where to generate keys and keep them safe
$ openssl req -new -x509 -newkey rsa:2048 -keyout MOK.priv -outform DER -out MOK.der -nodes -days 36500 -subj "/CN=Exein.io/"
$ mokutil --import MOK.der
input password:
input password again:
#the password you put here must match the one you'll put on the UEFI prompt on the next machine boot
```
After the machine have been rebooted, you need to use the key to sign the module:
```
# sign-file is an utility provided with the kernel, and can be found in the kernel source tree in the /script directory
sign-file sha256 MOK.priv MOK.der "$modfile"

```
Now the kernel module can be loaded and **it will work as intended**.
Please note that the Linux kernel will still complain about the fact that the module is out-of-tree.
`loading out-of-tree module taints kernel.`

# IBT
Newer Linux kernels support a counter measure against code
reuse attacks called [IBT](https://en.wikipedia.org/wiki/Indirect_Branch_Tracking).
But IBT not only prevents malicious code from achieving its goals. It also
lets earlier version of ALD crash when they call a function to figure out the location of
variable `kernel_locked_down`. This variable holds the current kernel lockdown status
and ALD sets it to 0 in order to disable lockdown.

ALD now offers two ways to work around IBT. These are as follows:

1.  Because the location of `kernel_locked_down` can be found
	in the virtual file `/proc/kallsym` (provided it is
	configured for your kernel), ALD allows the required address
	to be fed via the option parameter `kernel_locked_down_address`.

	Here is an example script, that shows how you can do this:

	```
	#!/bin/bash

	lockdownAddress=$(grep kernel_locked_down /proc/kallsyms | cut -b 1-16)
	modprobe ald kernel_locked_down_addr=0x${lockdownAddress}
	rmmod ald
	```

	You cannot go wrong here,
	because only the correct address of `kernel_locked_down` will be accepted.
	This is possible, as the function required to check whether an address belongs
	to a given variable name is not hindered by IBT.

2.  If the parameter `kernel_locked_down_address` is not provided
	or set to 0,
	IBT will temporarily be disabled for a short time
	but long enough to figure out the address of `kernel_locked_down`.

	So if you don't mind the short negative impact on security
	you can use ALD as before.

# Test
```
$ make -C /lib/modules/$(uname -r)/build M=$PWD modules
$ sign-file sha256 MOK.priv MOK.der ald.ko
$ sudo cat /sys/kernel/security/lockdown
none [integrity] confidentiality
$ sudo insmod ald.ko
$ sudo cat /sys/kernel/security/lockdown
[none] integrity confidentiality
```
