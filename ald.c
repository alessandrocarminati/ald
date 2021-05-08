#include <linux/module.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/kprobes.h>

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

int pre(struct kprobe *p, struct pt_regs *regs){
	return 0;
}

void post(struct kprobe *p, struct pt_regs *regs, unsigned long flags) {
}

int fault(struct kprobe *p, struct pt_regs *regs, int trapnr){
	return 0;
}

static struct kprobe k = {
    .symbol_name = "kallsyms_lookup_name",
    .pre_handler = pre,
    .post_handler = post,
    .fault_handler = fault
};

void *get_kallsyms_lookup_name_addr(void){
        void *ret;
	int dbg;

	DODEBUG(KERN_INFO "ald - get_kallsyms_lookup_name_addr");
        if ( (dbg=register_kprobe(&k)) < 0) {
		DODEBUG(KERN_INFO "ald - register_kprobe error %d\n", dbg);
		return NULL;
		}
	DODEBUG(KERN_INFO "ald - probe registered\n");
        ret = (void *) k.addr;
	DODEBUG(KERN_INFO "ald - kallsyms_lookup_nameis at %px\n", ret);
        unregister_kprobe(&k);
        return ret;
}

static int init(void){
	unsigned long (*kallsyms_lookup_name)(const char *);
	int *kld;

        kallsyms_lookup_name=get_kallsyms_lookup_name_addr();
	if (kallsyms_lookup_name) {
	        kld     = (int *) (*kallsyms_lookup_name)("kernel_locked_down");
		DODEBUG(KERN_INFO "kernel_locked_down is at 0x016 %p", kld);
		if (kld) {
			*kld=0;
			printk(KERN_INFO "ald - Module ready. Lockdown level resetted\n");
			} else {
				pr_info("ald - not supported for this kernel\n");
				}
		} else {
			pr_info("ald - can't get kallsyms_lookup_name addr\n");
			}
	return 0;
}

static void cleanup(void){
	printk(KERN_INFO "ald - Module removed.\n");
}

module_init(init);
module_exit(cleanup);

