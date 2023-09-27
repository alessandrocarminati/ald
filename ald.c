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

static unsigned long kernel_locked_down_addr = 0;
module_param(kernel_locked_down_addr, ulong, 0);
MODULE_PARM_DESC(kernel_locked_down_addr," kernel_locked_down_addr: Address where the kernel_locked_down symbol points to.");

#define KSYM_NAME_PLUS_OFFSETS ( KSYM_NAME_LEN + 1 + 19 + 1 + 19 )

static char symname[KSYM_NAME_PLUS_OFFSETS];
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
	kallsyms_lookup_name_t kallsyms_lookup_name;
	int *kld;
	unsigned long long save_msr;
	unsigned long long new_msr;
	int symname_len;

	kld = 0;

	if ( kernel_locked_down_addr ) {
		DODEBUG(KERN_INFO "ald - Parameter kernel_locked_down_addr is %lx", kernel_locked_down_addr);
		symname_len = sprint_symbol(symname, kernel_locked_down_addr);
	} else {
		DODEBUG(KERN_INFO "ald - Paramater kernel_locked_down_addr is 0 or not given.")
	}

	if ( kernel_locked_down_addr && ( strncmp(symname, targetSymname, symname_len) == 0 ) ) {
		DODEBUG(KERN_INFO "ald - The symbol of the address from the parameter actually matches %s.",
			targetSymname);
		kld = (int *) (kernel_locked_down_addr);
	} else {
		kernel_locked_down_addr = 0;
		DODEBUG(KERN_INFO "ald - The parameter kernel_locked_down_addr was not given or does not match %s. So ignoring paramter input.",
			targetSymname);

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
