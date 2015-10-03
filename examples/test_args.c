#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>

int
main (int argc, char *argv[])
{
	int i = 0;
	for (; i < argc; ++i)
	{
		printf("arg[%i] = %s\n", i, argv[i]);
	}
	exit(0);
}
