
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* This is the perf map to send events to userspace */
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	//__uint(max_entries, 2);	/* let libbpf determine it at load time based on num_cpus online */
} my_map SEC(".maps");

int global_counter = 0;
int clone_exit_counter = 0;
int exit_exit_counter = 0;
int exit_enter_counter = 0;
int exit_group_enter_counter = 0;

struct clone_enter_ctx {
	unsigned long long unused;
	int __syscall_nr;
	unsigned long clone_flags;
	unsigned long newsp;
	int * parent_tidptr;
	int * child_tidptr;
	unsigned long tls;
};

struct exit_enter_ctx {
	unsigned long long unused;
	int __syscall_nr;
	long error_code;
};
struct exit_exit_ctx {
	unsigned long long unused;
	int __syscall_nr;
	long ret;
};
struct clone_exit_ctx {
	unsigned long long unused;
	int __syscall_nr;
	long ret;
};
/*
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:unsigned long clone_flags;	offset:16;	size:8;	signed:0;
	field:unsigned long newsp;	offset:24;	size:8;	signed:0;
	field:int * parent_tidptr;	offset:32;	size:8;	signed:0;
	field:int * child_tidptr;	offset:40;	size:8;	signed:0;
	field:unsigned long tls;	offset:48;	size:8;	signed:0;
*/

static inline int match_app_name(void)
{
	char name[] = "hccl_demo";
	char comm[256];

	bpf_get_current_comm(&comm, sizeof(comm));

	for (int i = 0; i < sizeof(name); i++) {
		if (comm[i] != name[i])
			return -1;
	}
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone")
int trace_clone_enter(struct clone_enter_ctx *ctx)
{

	if (match_app_name())
		return 0;

	global_counter++;
	bpf_printk("sys_enter_clone, counter = %d", global_counter);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_clone")
int trace_clone_exit(struct clone_exit_ctx *ctx)
{
	if (match_app_name())
		return 0;

	if (ctx->ret < 0)
		bpf_printk("clone() failed, ret = %ld", ctx->ret);

	clone_exit_counter++;
	bpf_printk("sys_exit_clone, counter = %d,    return_value = %ld", clone_exit_counter, ctx->ret);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit_group")
int trace_exit_group_enter(struct exit_enter_ctx *ctx)
{
	if (match_app_name())
		return 0;
	exit_group_enter_counter++;
	bpf_printk("sys_enter_exit_group, counter = %d", exit_group_enter_counter);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit")
int trace_exit_enter(struct exit_enter_ctx *ctx)
{
	if (match_app_name())
		return 0;
	exit_enter_counter++;
	bpf_printk("sys_enter_exit, counter = %d", exit_enter_counter);
	return 0;
}
SEC("tracepoint/syscalls/sys_exit_exit")
int trace_exit_exit(struct exit_exit_ctx *ctx)
{
	if (match_app_name())
		return 0;
	exit_exit_counter++;
	bpf_printk("sys_exit_exit, counter = %d,    return_value = %ld", exit_exit_counter, ctx->ret);
	return 0;
}
char _license[] SEC("license") = "GPL";
