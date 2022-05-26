vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

trial:
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I ../libbpf/build -I /usr/src/linux-headers-5.13.0-39/include/ -I /usr/src/linux-headers-5.13.0-39/arch/mips/include/ -I /usr/include/x86_64-linux-gnu/ -c trial.bpf.c -o trial.bpf.o
	bpftool gen skeleton trial.bpf.o > trial.skel.h
	clang -g -O2 -Wall -I ../libbpf/build -c trial.c -o trial.o
	clang -Wall -O2 -g trial.o ../libbpf/build/libbpf.a -lelf -lz -o trial

xdper:
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I ../libbpf/build -I /usr/src/linux-headers-5.13.0-39/include/ -I /usr/src/linux-headers-5.13.0-39/arch/mips/include/ -I /usr/include/x86_64-linux-gnu/ -c xdper.bpf.c -o xdper.bpf.o
	bpftool gen skeleton xdper.bpf.o > xdper.skel.h
	clang -g -O2 -Wall -I ../libbpf/build -c xdper.c -o xdper.o
	clang -Wall -O2 -g xdper.o ../libbpf/build/libbpf.a -lelf -lz -o xdper

trace: tracer.bpf.c tracer.c
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I ../libbpf/build -I /usr/src/linux-headers-5.13.0-39/include/ -I /usr/include/x86_64-linux-gnu/ -c tracer.bpf.c -o tracer.bpf.o
	bpftool gen skeleton tracer.bpf.o > tracer.skel.h
	clang -g -O2 -Wall -I ../libbpf/build -c tracer.c -o tracer.o
	clang -Wall -O2 -g tracer.o ../libbpf/build/libbpf.a -lelf -lz -o tracer

trafcon: trafcon.bpf.c trafcon.c
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I ../libbpf/build -I /usr/src/linux-headers-5.13.0-39/include/ -I /usr/include/x86_64-linux-gnu/ -c trafcon.bpf.c -o trafcon.bpf.o
	bpftool gen skeleton trafcon.bpf.o > trafcon.skel.h
	clang -g -O2 -Wall -I ../libbpf/build -c trafcon.c -o trafcon.o
	clang -Wall -O2 -g trafcon.o ../libbpf/build/libbpf.a -lelf -lz -o trafcon

skfilter: skfilter.bpf.c skfilter.c
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I ../libbpf/build -I /usr/src/linux-headers-5.13.0-39/include/ -I /usr/include/x86_64-linux-gnu/ -c skfilter.bpf.c -o skfilter.bpf.o
	bpftool gen skeleton skfilter.bpf.o > skfilter.skel.h
	clang -g -O2 -Wall -I ../libbpf/build -c skfilter.c -o skfilter.o
	clang -Wall -O2 -g skfilter.o ../libbpf/build/libbpf.a -lelf -lz -o skfilter

clean:
	rm -f *.o
	rm -f *.skel.h
	rm -f trial
	rm -f xdper
	rm -f tracer
	rm -f trafcon
	rm -f skfilter