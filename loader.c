#include <stdio.h>
#include <bpf/libbpf.h>
#include "common.h"

static void event_cb(void *ctx, int cpu, void *data, unsigned int size)
{
	
	struct event *e = data;
	printf("Got event, cpu = %d size = %u event_size = %lu msg = \n", cpu, size, e->size);
	for (size_t i = 0; i < e->size; i++) {
		printf("%c", e->data[i]);
	}
	printf("\n--------------------------------------------------------------------\n");
}

int main(int argc, char **argv)
{

	struct perf_buffer_opts pb_opts = {};
	struct perf_buffer *pb;
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_link *link = NULL;
	long err;
	int map_fd;

	obj = bpf_object__open("./EXE");
	if (libbpf_get_error(obj)) {
		printf("Unable to parse eBPF objects in file\n");
		return -1;
	}
	printf("Open was good\n");

	if(bpf_object__load(obj)) {
		printf("Something wrong with load \n");
		return -1;
	}
	printf("Load was good\n");


	map_fd = bpf_object__find_map_fd_by_name(obj, "my_map");
	if (map_fd < 0) {
		printf("ERROR: finding perf map in obj file failed\n");
		goto cleanup;
	}
	
/*
	prog = bpf_object__find_program_by_name(obj, "bpf_prog");
    if (!prog) {
        fprintf(stderr, "ERROR: finding a prog in obj file failed\n");
        goto cleanup;
    }

	printf("Program found\n");

    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "ERROR: bpf_program__attach failed\n");
        link = NULL;
    }
*/

	//pb_opts.sample_cb = event_cb;
	pb = perf_buffer__new(map_fd, 8, event_cb, NULL, NULL, NULL); /* 32KB */
	if (libbpf_get_error(pb)) {
		printf("failed to setup perf_buffer\n");
		return 1;
	}

	bpf_object__for_each_program(prog, obj) {
		printf("Attaching one\n");
		link = bpf_program__attach(prog);
		if (libbpf_get_error(link)) {
			fprintf(stderr, "ERROR: bpf_program__attach failed\n");
			link = NULL;
			goto cleanup;
		}
		printf("Got a link\n");
	}

	printf("Polling for events\n");
	while(perf_buffer__poll(pb, 1000) >= 0);

cleanup:

	return 0;
}
