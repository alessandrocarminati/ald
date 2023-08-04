#include <linux/module.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/moduleparam.h>
#include <asm/msr.h>

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

static unsigned long lockdown_addr = 0;
module_param(lockdown_addr, ulong, 0);
MODULE_PARM_DESC(lockdown_addr," lockdown_addr: Address where the kernel_lockdown symbol points to.");

static char symname[2048];
static char targetSymname[] = "kernel_locked_down+0x0/0x4\0";


typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

int pre(struct kprobe *p, struct pt_regs *regs){
	return 0;
}

static void post(struct kprobe *p, struct pt_regs *regs, unsigned long flags) {
}

/* int fault(struct kprobe *p, struct pt_regs *regs, int trapnr){ */
/* 	return 0; */
/* } */

static struct kprobe k = {
    .symbol_name = "kallsyms_lookup_name",
    .pre_handler = pre,
    .post_handler = post
    // .fault_handler = fault
};

static kallsyms_lookup_name_t get_kallsyms_lookup_name_addr(void){
        kallsyms_lookup_name_t ret;
	int dbg;

	DODEBUG(KERN_INFO "ald - get_kallsyms_lookup_name_addr");
        if ( (dbg=register_kprobe(&k)) < 0) {
		DODEBUG(KERN_INFO "ald - register_kprobe error %d\n", dbg);
		return NULL;
		}
	DODEBUG(KERN_INFO "ald - probe registered\n");
        ret = (kallsyms_lookup_name_t) k.addr;
	DODEBUG(KERN_INFO "ald - kallsyms_lookup_name is at %px\n", ret);

        unregister_kprobe(&k);
        return ret;
}

static int init(void){
	unsigned long (*kallsyms_lookup_name)(const char *name);
	//kallsyms_lookup_name_t kallsyms_lookup_name __attribute__ ( nocf_check);
	int *kld;
	unsigned long long save_msr;
	unsigned long long new_msr;

	kld = 0;

	if ( lockdown_addr ) {
		DODEBUG(KERN_INFO "ald - lockdown_addr is %lx", lockdown_addr);
		sprint_symbol(symname, lockdown_addr);
		DODEBUG(KERN_INFO "ald - ... this address acutally points at %s", symname);
	} else {
		DODEBUG(KERN_INFO "ald - Parmater lockdown_addr is 0 or not given.")
	}

	if ( lockdown_addr && ( strcmp(symname, targetSymname) == 0 ) ) {
		kld = (int *) (lockdown_addr);
	} else {
		lockdown_addr = 0;
		DODEBUG(KERN_INFO "ald - Parameter not pointing to the expected symbol. So ignoring paramter input.");

		kallsyms_lookup_name=get_kallsyms_lookup_name_addr();

		if (kallsyms_lookup_name) {
			rdmsrl(MSR_IA32_S_CET, save_msr);
			if ( (save_msr & CET_ENDBR_EN) ) {
				DODEBUG(KERN_INFO "ald - IBT is enabled");
				new_msr = save_msr & (~ CET_ENDBR_EN);
				wrmsrl(MSR_IA32_S_CET, new_msr);
				DODEBUG(KERN_INFO "ald - IBT temporarily disabled");
			};
			kld = (int *) (*kallsyms_lookup_name)("kernel_locked_down");
			DODEBUG(KERN_INFO "ald - kernel_locked_down from kallsyms_lookup_name at %px", kld);
			//DODEBUG(KERN_INFO " ... this address acutally points at %s", symname);
			if ( (save_msr & CET_ENDBR_EN) ) {
				DODEBUG(KERN_INFO "ald - restoring IBT");
				wrmsrl(MSR_IA32_S_CET, save_msr);
			};
		} else {
			pr_info("ald - can't get kallsyms_lookup_name addr\n");
		}
	};

	if (kld) {
		*kld = 0;
		printk(KERN_INFO "ald - Module ready. Lockdown level reset.\n");
	} else {
		pr_info("ald - not supported for this kernel or kernel_locked_down could not be located.\n");
	}
	return 0;
}

static void cleanup(void){
	printk(KERN_INFO "ald - Module removed.\n");
}

module_init(init);
module_exit(cleanup);
