#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <lib/kernel/console.h>
#include <string.h>

static void syscall_handler (struct intr_frame *);
static void sys_write(struct intr_frame *f);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f)
{
	int syscalln;
	memcpy(&syscalln, f->esp, 4);
	switch(syscalln)
	{
	case SYS_WRITE: sys_write(f); break;
	default:
	{
		printf ("system call!\n");
		thread_exit ();
	}
	}
  //printf ("system call!\n");
  //thread_exit ();
}


static void sys_write(struct intr_frame *f)
{
	//test argument passing. write to console
	const char* buf;
	size_t size;

	memcpy(&buffer, f->esp + 8, 4);
	memcpy(&size, f->esp + 12, 4);

	putbuf(buffer, asize);
	f->eax = asize;
}
