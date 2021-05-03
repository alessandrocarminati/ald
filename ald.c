#include <linux/module.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/slab.h>

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Alessandro Carminati");

#define DEBUG

#ifndef DODEBUG
#ifdef DEBUG
#define DODEBUG(fmt, ... ) printk(fmt, ##__VA_ARGS__ );
#else
#define DODEBUG(fmt, ... ) do { } while(0)
#endif
#endif


static int __init kernel_readf(struct file *file, unsigned long offset, char *addr, unsigned long count){
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
	return kernel_read(file, offset, addr, count);
#else
	loff_t pos = offset;
	return kernel_read(file, addr, count, &pos);
#endif
}

static void *kallsyms_ge_57(const char *name){
	struct file *file = NULL;
	char *buf;
	unsigned long entry = 0;
	struct file_system_type *fstype = get_fs_type("proc");
	struct vfsmount *mnt = vfs_kern_mount(fstype, 0, "proc", NULL);
	struct dentry *root;
	struct dentry *dentry;
	if (fstype) module_put(fstype->owner);
	if (IS_ERR(mnt)) return (void *) entry;
	root = dget(mnt->mnt_root);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
	inode_lock(root->d_inode);
	dentry = lookup_one_len("kallsyms", root, 8);
	inode_unlock(root->d_inode);
#else
	mutex_lock(&root->d_inode->i_mutex);
	dentry = lookup_one_len("kallsyms", root, 8);
	mutex_unlock(&root->d_inode->i_mutex);
#endif

	dput(root);
	if (IS_ERR(dentry)) mntput(mnt);
		else {
			struct path path = { .mnt = mnt, .dentry = dentry };
			file = dentry_open(&path, O_RDONLY, current_cred());
			}
	if (!(IS_ERR(file) || !file)){
		buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
		if (buf) {
			int len;
			int offset = 0;
			while ((len = kernel_readf(file, offset, buf, PAGE_SIZE - 1)) > 0) {
				char *cp;
				buf[len] = '\0';
				cp = strrchr(buf, '\n');
				if (!cp)
					break;
				*(cp + 1) = '\0';
				offset += strlen(buf);
				cp = strstr(buf, name);
				if (!cp)
					continue;
				*cp = '\0';
				while (cp > buf && *(cp - 1) != '\n')
					cp--;
				entry = simple_strtoul(cp, NULL, 16);
				break;
			}
			kfree(buf);
		}
		filp_close(file, NULL);
		}
	return (void *) entry;
}

static int init(void){
        int *kld     = (void *) kallsyms_ge_57("kernel_locked_down");
	DODEBUG(KERN_INFO "kernel_locked_down is at 0x016 %p", kld);
	*kld=0;
	printk(KERN_INFO "ald - Module ready. Lockdown level resetted\n");
	return 0;
}

static void cleanup(void){
	printk(KERN_INFO "ald - Module removed.\n");
}

module_init(init);
module_exit(cleanup);

