//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>


struct xdp_exception_ctx {
    __u16 common_type;
    __u8 flags;
    __u8 common_preempt_count;
    __s32 common_pid;

    __s32 prog_int;
    __u32 act;
    __s32 ifindex;
};

//help from: https://ancat.github.io/kernel/2021/05/20/hooking-processes-and-threads.html
// root@ubuntu-s-2vcpu-4gb-120gb-intel-lon1-01:~/syscall-counter# cat /sys/kernel/tracing/events/sched/sched_process_fork/format 

struct sched_process_fork_t {
    unsigned short common_type;          // Offset: 0,  Size: 2
    unsigned char common_flags;          // Offset: 2,  Size: 1
    unsigned char common_preempt_count;  // Offset: 3,  Size: 1
    int common_pid;                      // Offset: 4,  Size: 4

    char parent_comm[16];                // Offset: 8,  Size: 16
    __u32 parent_pid;                    // Offset: 24, Size: 4
    char child_comm[16];                 // Offset: 28, Size: 16
    __u32 child_pid;                     // Offset: 44, Size: 4
};


//we can't us execve because not every process creation
//uses execve, fork() and clone() can be called without exec()
SEC("tracepoint/sched/sched_process_fork")
int detect_new_process(struct sched_process_fork_t *ctx) {
    bpf_printk("pid of parent process is %ld with command %s", ctx->parent_pid, ctx->parent_comm);
    bpf_printk("pid of new child process is %ld with command %s", ctx->child_pid, ctx->child_comm);
    return 0;
}


char __license[] SEC("license") = "GPL";