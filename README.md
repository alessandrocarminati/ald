# ALD
Since the Linux 5.4 when the lockdown LSM has been implemented, the current linux 5.9.1 has not yet implemented any option to lift kernel lockdown status.
The `SysReq+x` mentioned on the `man kernel_lockdown.7`, is still not yet been integrated with the main branch.
More info, please check [my blog](http://carminatialessandro.blogspot.com/2020/10/kernel-lockdown.html)
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
