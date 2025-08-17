#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/compiler.h>
#include <linux/types.h>
#include <asm/unistd.h>  

MODULE_LICENSE("GPL");
MODULE_AUTHOR("moeein");
MODULE_DESCRIPTION("Print addresses of all Linux syscalls :)))");
MODULE_VERSION("1.0");

static void **sys_call_table_ptr;

static int __init syscall_dump_init(void)
{
	int ret;
	unsigned int i;
	struct kprobe kp = {
		.symbol_name = "sys_call_table",
	};

	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("syscall_dump: register_kprobe failed: %d\n", ret);
		return ret;
	}

	sys_call_table_ptr = (void **)kp.addr;
	unregister_kprobe(&kp);

	if (!sys_call_table_ptr) {
		pr_err("syscall_dump: sys_call_table is NULL\n");
		return -EINVAL;
	}

	pr_info("syscall_dump: sys_call_table @ %px\n", sys_call_table_ptr);
	pr_info("syscall_dump: NR_syscalls = %u\n", (unsigned int)NR_syscalls);

	for (i = 0; i < (unsigned int)NR_syscalls; i++) {
		void *entry = READ_ONCE(sys_call_table_ptr[i]);
		if (!entry)
			continue;
		pr_info("syscall_dump: %4u: %px (%pS)\n", i, entry, entry);
	}

	pr_info("syscall_dump: done.\n");
	return 0;
}

static void __exit syscall_dump_exit(void)
{
	pr_info("syscall_dump: unloaded.\n");
}

module_init(syscall_dump_init);
module_exit(syscall_dump_exit);