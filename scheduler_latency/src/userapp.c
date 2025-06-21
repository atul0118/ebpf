#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char *argv[])
{
	int val = 0;
	while (1) {
		printf("PID=%d val=%d\n", getpid(), val++);
		sleep(1);
	}
	return 0;
}
