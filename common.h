#ifndef __COMMON_H
#define __COMMON_H

#include <linux/uio.h>
#include <stddef.h>

struct event {
	size_t size;
	char data[0];
};

#ifndef APP_NAME
#define APP_NAME "nginx"
#endif

#define HEAP_BUFFER_SIZE (30 * 1024)
#define PERF_MAP_SPACE (HEAP_BUFFER_SIZE - sizeof(struct event))

#define MIN(a,b) (((a)<(b))?(a):(b))

struct recvfrom_enter_ctx {
	unsigned long long unused;
	int __syscall_nr;
	int padding;
	long fd;
	void* ubuf;
	size_t size;
	unsigned int flags;
	void* addr;
	int* addr_len;
};

struct recvfrom_exit_ctx {
	unsigned long long unused;
	int __syscall_nr;
	long ret;
};

struct read_enter_ctx {
	unsigned long long unused;
	int __syscall_nr;
	//unsigned int padding;
	unsigned long fd;
	char* buf;
	size_t count;
};

struct read_exit_ctx {
	unsigned long long unused;
	int __syscall_nr;
	long ret;
};

struct write_enter_ctx {
	unsigned long long unused;
	int __syscall_nr;
	unsigned long fd;
	char* buf;
	size_t count;
};

struct write_exit_ctx {
	unsigned long long unused;
	int __syscall_nr;
	long ret;
};

struct sendxx_enter_ctx {
	unsigned long long unused;
	int __syscall_nr;
	unsigned long fd;
	char* buf;
	size_t count;
	unsigned long flags;
};

struct sendxx_exit_ctx {
	unsigned long long unused;
	int __syscall_nr;
	long ret;
};

struct writev_enter_ctx {
	unsigned long long unused;
	int __syscall_nr;
	unsigned long fd;
	const struct iovec *vec;
	unsigned long vlen;
};

struct writev_exit_ctx {
	unsigned long long unused;
	int __syscall_nr;
	long ret;
};

#endif /* __COMMON_H */
