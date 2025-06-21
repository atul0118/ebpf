### What is this program?
* This program tracks and shows scheduler latency for a task.
* Scheduler latency means the time spent by a task in runnable state, before it finally gets a cpu to run.
* This program comes with bpf related code, sched_latency.c, sched_latency.bpf.c and sched_latency.h
* There is also a test app, userapp.c, which can be run to verify the ebpf code. This is a simple program that countinuously sleeps for 1 sec and prints a counter value.

### How to use this program?
* You need bpftool and libbpf source to compile this program. These instructions work for x86_64 machine.
* However with correct libbpf, libz and libelf, the program can also be compiled for other architectures like aarch64.
* To build the program, update **BPFTOOL** and **LIBBPF_SRC** in Makefile.
* Build the program: **make**
* This will create two executables, sched_latency and userapp.
* Run **userapp**. This will start the application with output something like:

	```
	$ ./userapp
	PID=60972 val=0
	PID=60972 val=1
	PID=60972 val=2
	PID=60972 val=3
	```
* Now run sched_latency in another terminal: **sudo ./sched_latency -p PID**

	```
	$ sudo ./sched_latency -p 60972
	[sudo] password for atom:
	pid to track = 60972
	[Scheduling Latency]:	comm:userapp	PID:60972	Latency:48360 ns
	[Scheduling Latency]:	comm:userapp	PID:60972	Latency:47488 ns
	[Scheduling Latency]:	comm:userapp	PID:60972	Latency:47831 ns
	[Scheduling Latency]:	comm:userapp	PID:60972	Latency:47668 ns
	[Scheduling Latency]:	comm:userapp	PID:60972	Latency:47428 ns
	^C
	CTRL-C pressed. Exiting ...

	```
* The **Latency** data above shows the time spent by the task waiting for the cpu. We can run **sched_latency** with any desired PID.
* If you want to check the kernel debug messages from the ebpf code, just read the traces: **cat /sys/kernel/tracing/trace**


