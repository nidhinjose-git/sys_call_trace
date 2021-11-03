This is an example to demonstrate tracing system calls using ebpf programs by running them at various syscall tracepoints. The various syscalls traced in this demo are
read(), recvfrom(), write(), and sendto(). 

Build
----

User application will be statically linked to libbpf. To facilitate that, the build machine needs static libbpf.a library and its path must be exported before invoking the make.

1. export LIBBPF. Populate LIBBPF variable with the path of the libbpf.a archive file.

2. Run make.
```shell
$ export LIBBPF="/home/vagrant/libbpf.a"  #Use appropriate path here
$ make
```

A successfull invocation of make generates the user application 'loader' and the bpf object file 'EXE'

By default, the resulting ebpf program will trace application named 'nginx'. To build the ebpf code for intercepting applications other than 'nginx', pass the application name with -DAPP_NAME macro.
For example,
```shell
$ make CFLAGS='-DAPP_NAME=\"server\"'
```

The resulting ebpf binary will trace applications named 'server'

Running the application
----------------------

```shell
$ ./loader
```


How to get static library libbpf.a
------------------------------------
libbpf source code is available at https://github.com/libbpf/libbpf
The page has instructions on how to build a static libbpf.a archive.
