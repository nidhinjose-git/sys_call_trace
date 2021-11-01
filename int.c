#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "common.h"

struct writev_iovec{
	const struct iovec *vec;
	unsigned long vlen;
};

/* MAP used to save write()/sendto() user buffer address */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, void*);
} saved_write_ctx SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct writev_iovec);
} saved_writev_ctx SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, void*);
} saved_rcvfrom_ctx SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, void*);
} saved_read_ctx SEC(".maps");

/* This is the perf map to send events to userspace */
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	//__uint(max_entries, 2);	/* let libbpf determine it at load time based on num_cpus online */
} my_map SEC(".maps");


struct heap_buffer {
	char buf[HEAP_BUFFER_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct heap_buffer);
} heap SEC(".maps");



#if 0
SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(void *ctx) 
{
	char msg[] = "123";
	char err_msg[] = "Failed to write to perf buffer";
	char copy_err[] = "Failed to copy string to heap memory";
	char umsg[] = "Msg to userspace";
	struct event *e;
	int zero = 0;
	long written;

	e = bpf_map_lookup_elem(&heap, &zero);
	if (!e) {
		return 0;
	}
	
	written = bpf_probe_read_str(&e->data, HEAP_BUFFER_SIZE - sizeof(struct event), umsg);
	if (written < 0) {
		bpf_trace_printk(copy_err, sizeof(copy_err));
		return 0;
	}
	e->size = written;

	//BPF_F_CURRENT_CPU
	if (bpf_perf_event_output(ctx, &my_map, BPF_F_CURRENT_CPU, e, sizeof(*e) + written) < 0) {
		bpf_trace_printk(err_msg, sizeof(err_msg));
	} else {
		bpf_trace_printk(msg, sizeof(msg));
	}
	return 0;
}

#endif

__attribute__((always_inline))
int trace_sendxx_enter(struct sendxx_enter_ctx *ctx)
{
    char name[] = APP_NAME;
    char comm[256];
	int zero = 0;

	bpf_get_current_comm(&comm, sizeof(comm));

	for (int i = 0; i < sizeof(name); i++) {
		if (comm[i] != name[i]) {
			//bpf_trace_printk("the string value is something else--> |%s|\\n", comm);
			return 0;
		}
	}

	//bpf_printk("read() system call, addr = %x   count = %u", (unsigned long long)ctx->buf, ctx->count);
	void *p = ctx->buf;
	bpf_map_update_elem(&saved_write_ctx, &zero, &p, BPF_ANY);
	return 0;
}

__attribute__((always_inline))
int trace_sendxx_exit(struct sendxx_exit_ctx *ctx)
{
	struct event *e;
	char name[] = APP_NAME;
	char comm[256];
	int zero = 0;

	bpf_get_current_comm(&comm, sizeof(comm));

	for (int i = 0; i < sizeof(APP_NAME); i++) {
		if (comm[i] != name[i]) {
			//bpf_trace_printk("the string value is something else--> |%s|\\n", comm);
			return 0;
		}
	}

	bpf_printk("sendxx() exit call, ret = %ld", ctx->ret);

	void **ubuf = bpf_map_lookup_elem(&saved_write_ctx, &zero);
	if (!ubuf) {
		return 0;
	}

	if (ctx->ret <= 0) {
		return 0;
	}

	e = bpf_map_lookup_elem(&heap, &zero);
	if (!e) {
		bpf_printk("perf map lookup failed, Impossible");
		return 0;
	}

	long min = MIN(ctx->ret, PERF_MAP_SPACE);
	if (bpf_probe_read_user(e->data, min, *ubuf)) {
		bpf_printk("Failed to copy userspace buffer to heap");
		return 0;
	}

	e->size = min;
	if (bpf_perf_event_output(ctx, &my_map, BPF_F_CURRENT_CPU, e, sizeof(struct event) + min)) {
		bpf_printk("Failed to copy heap to perf buffer");
		return 0;
	}
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_send_enter(struct sendxx_enter_ctx *ctx) {

	return trace_sendxx_enter(ctx);
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int trace_send_exit(struct sendxx_exit_ctx *ctx) {

	return trace_sendxx_exit(ctx);
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write_enter(struct write_enter_ctx *ctx)
{
    char name[] = APP_NAME;
    char comm[256];
	int zero = 0;

	bpf_get_current_comm(&comm, sizeof(comm));

	for (int i = 0; i < sizeof(name); i++) {
		if (comm[i] != name[i]) {
			//bpf_trace_printk("the string value is something else--> |%s|\\n", comm);
			return 0;
		}
	}

	//bpf_printk("read() system call, addr = %x   count = %u", (unsigned long long)ctx->buf, ctx->count);
	void *p = ctx->buf;
	bpf_map_update_elem(&saved_write_ctx, &zero, &p, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int trace_write_exit(struct write_exit_ctx *ctx)
{
	struct event *e;
	char name[] = APP_NAME;
	char comm[256];
	int zero = 0;

	bpf_get_current_comm(&comm, sizeof(comm));

	for (int i = 0; i < sizeof(APP_NAME); i++) {
		if (comm[i] != name[i]) {
			//bpf_trace_printk("the string value is something else--> |%s|\\n", comm);
			return 0;
		}
	}

	//bpf_printk("\nread() exit call, diff = %d   sizeof(int) %u", (char*)&ctx->ret - (char*)ctx, sizeof(int));
	bpf_printk("write() exit call, ret = %ld", ctx->ret);

	void **ubuf = bpf_map_lookup_elem(&saved_write_ctx, &zero);
	if (!ubuf) {
		return 0;
	}

	if (ctx->ret <= 0) {
		return 0;
	}

	e = bpf_map_lookup_elem(&heap, &zero);
	if (!e) {
		bpf_printk("perf map lookup failed, Impossible");
		return 0;
	}

	long min = MIN(ctx->ret, PERF_MAP_SPACE);
	if (bpf_probe_read_user(e->data, min, *ubuf)) {
		bpf_printk("Failed to copy userspace buffer to heap");
		return 0;
	}

	e->size = min;
	if (bpf_perf_event_output(ctx, &my_map, BPF_F_CURRENT_CPU, e, sizeof(struct event) + min)) {
		bpf_printk("Failed to copy heap to perf buffer");
		return 0;
	}
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int trace_writev_enter(struct writev_enter_ctx *ctx)
{
    char name[] = APP_NAME;
    char comm[256];
	struct writev_iovec ubuf;
	int zero = 0;

	bpf_get_current_comm(&comm, sizeof(comm));

	for (int i = 0; i < 6; i++) {
		if (comm[i] != name[i]) {
			//bpf_trace_printk("sys_enter_writev: the string value is something else--> |%s|\\n", comm);
			return 0;
		}
	}
	//bpf_printk("writev() system call,  vec = %d", (char*)&ctx->vec - (char*)ctx);

	ubuf.vec = ctx->vec;
	ubuf.vlen = ctx->vlen;
	bpf_map_update_elem(&saved_writev_ctx, &zero, &ubuf, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_writev")
int trace_writev_exit(struct writev_exit_ctx *ctx)
{
	struct event *e;
    char name[] = APP_NAME;
    char comm[256];
	int zero = 0;

	bpf_get_current_comm(&comm, sizeof(comm));

	for (int i = 0; i < 6; i++) {
		if (comm[i] != name[i]) {
			//bpf_trace_printk("sys_exit_writev: the string value is something else--> |%s|\\n", comm);
			return 0;
		}
	}
	bpf_printk("writev() system exit call,  ret_offset= %d  ctx->ret = %ld", (char*)&ctx->ret - (char*)ctx, ctx->ret);

	if (ctx->ret <= 0) {
		return 0;
	}

	struct writev_iovec *ubuf = bpf_map_lookup_elem(&saved_writev_ctx, &zero);
	if (!ubuf) {
		return 0;
	}

	e = bpf_map_lookup_elem(&heap, &zero);
	if (!e) {
		bpf_printk("perf map lookup failed, Impossible");
		return 0;
	}
	
	unsigned long min_vectors = MIN(64, ubuf->vlen);
	unsigned long max_bytes = MIN((unsigned long)ctx->ret, PERF_MAP_SPACE);
	unsigned long written = 0;
	for (unsigned long i = 0; i < min_vectors; i++) {

		struct iovec iov;
		if (bpf_probe_read_user(&iov, sizeof(struct iovec), ubuf->vec + i)) {

			bpf_printk("Failed to copy userspace iovec entry %u to stack", i);
			return 0;
		}
		unsigned long min = iov.iov_len;
		//if (iov.iov_len >= (max_bytes - written)) {
		if (min >= max_bytes) {
			break;
		}
		//unsigned long min = MIN(MIN(ctx->ret, PERF_MAP_SPACE) - written, iov.iov_len);
		//unsigned long min = MIN(ctx->ret, PERF_MAP_SPACE);
	#if 1
		char *addr = e->data + written;
		if ((addr + min) >= (e->data + PERF_MAP_SPACE - 1)) {
			break;
		}

		if (bpf_probe_read_user(addr, min, iov.iov_base)) {
		//if (bpf_probe_read_user(e->data + written, min, iov.iov_base)) {
		//if (bpf_probe_read_user(e->data, min, iov.iov_base)) {
			bpf_printk("Failed to copy userspace buffer to heap");
			return 0;
		}
	#endif
		written += min;
		//written += iov.iov_len;
		//max_bytes -= iov.iov_len;
	}

	bpf_printk("writev_exit: written %lu bytes", written);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int trace_recvfrom_exit(struct recvfrom_exit_ctx *ctx)
{
	struct event *e;
    char name[] = APP_NAME;
    char comm[256];
	int zero = 0;

	bpf_printk("recvfrom() exit, ret diff = %d   ctx->ret = %ld", (char*)&ctx->ret - (char*)ctx, ctx->ret);
    bpf_get_current_comm(&comm, sizeof(comm));

    for (int i = 0; i < sizeof(name); i++) {
        if (comm[i] != name[i]) {
            bpf_printk("sys_exit_recvfrom: the string value is something else--> |%s|\n\n", comm);
            return 0;
        }
    }

	void **ubuf = bpf_map_lookup_elem(&saved_rcvfrom_ctx, &zero);
	if (!ubuf) {
		return 0;
	}

	if (ctx->ret <= 0) {
		return 0;
	}

	e = bpf_map_lookup_elem(&heap, &zero);
	if (!e) {
		bpf_printk("perf map lookup failed, Impossible");
		return 0;
	}

	long min = MIN(ctx->ret, PERF_MAP_SPACE);
	if (bpf_probe_read_user(e->data, min, *ubuf)) {
		bpf_printk("Failed to copy userspace buffer to heap");
		return 0;
	}

	e->size = min;
	if (bpf_perf_event_output(ctx, &my_map, BPF_F_CURRENT_CPU, e, sizeof(struct event) + min)) {
		bpf_printk("Failed to copy heap to perf buffer");
		return 0;
	}
	return 0;
}


SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_recvfrom_enter(struct recvfrom_enter_ctx *ctx)
{
	char name[] = APP_NAME;
	char comm[256];
	void *p;
	int zero = 0;

	bpf_get_current_comm(&comm, sizeof(comm));

	for (int i = 0; i < 6; i++) {
		if (comm[i] != name[i]) {
			//bpf_trace_printk("the string value is something else--> |%s|\\n", comm);
			return 0;
		}
	}

	p = ctx->ubuf;
	bpf_map_update_elem(&saved_rcvfrom_ctx, &zero, &p, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int trace_read_enter(struct read_enter_ctx *ctx)
{
	char name[] = "server";
	char comm[256];

	bpf_get_current_comm(&comm, sizeof(comm));

	for (int i = 0; i < 7; i++) {
		if (comm[i] != name[i]) {
			//bpf_trace_printk("the string value is something else--> |%s|\\n", comm);
			return 0;
		}
	}

	//bpf_printk("read() system call, addr = %x   count = %u", (unsigned long long)ctx->buf, ctx->count);
	int zero = 0;
	void *p = ctx->buf;
	bpf_map_update_elem(&saved_read_ctx, &zero, &p, BPF_ANY);
	return 0;
}


SEC("tracepoint/syscalls/sys_exit_read")
int trace_read_exit(struct read_exit_ctx *ctx)
{
	struct event *e;
	char name[] = "server";
	char comm[256];
	int zero = 0;

	bpf_get_current_comm(&comm, sizeof(comm));

	for (int i = 0; i < 7; i++) {
		if (comm[i] != name[i]) {
			//bpf_trace_printk("the string value is something else--> |%s|\\n", comm);
			return 0;
		}
	}

	//bpf_printk("\nread() exit call, diff = %d   sizeof(int) %u", (char*)&ctx->ret - (char*)ctx, sizeof(int));
	bpf_printk("read() exit call, ret = %ld", ctx->ret);

	void **ubuf = bpf_map_lookup_elem(&saved_read_ctx, &zero);
	if (!ubuf) {
		return 0;
	}

	if (ctx->ret <= 0) {
		return 0;
	}

	e = bpf_map_lookup_elem(&heap, &zero);
	if (!e) {
		bpf_printk("perf map lookup failed, Impossible");
		return 0;
	}

	long min = MIN(ctx->ret, PERF_MAP_SPACE);
	if (bpf_probe_read_user(e->data, min, *ubuf)) {
		bpf_printk("Failed to copy userspace buffer to heap");
		return 0;
	}

	e->size = min;
	if (bpf_perf_event_output(ctx, &my_map, BPF_F_CURRENT_CPU, e, sizeof(struct event) + min)) {
		bpf_printk("Failed to copy heap to perf buffer");
		return 0;
	}
	return 0;
}

char _license[] SEC("license") = "GPL";

