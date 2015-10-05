#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <lib/kernel/console.h>
#include <string.h>

static int get_int_32(const void* ptr_)

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

	int syscalln = get_int_32(f->esp);
	switch(syscalln)
	{
		case SYS_WRITE: f->eax = sys_write(f); break;
		default:
		{
			thread_exit ();
		}
	}
}


static int sys_write(unsigned int fd, const char *buf, size_t count);
{
	if(!buf || buf+size-1 >= PHYS_BASE || get_int_32(buf) == -1) exit(-1);
	switch(fd)
	{
		case 0: exit(-1);
		case 1:
		{
			size_t written = 0;
			while(written + 128 < count)
			{
				putbuf(buf+written, 128);
				writen += 128;
			}
			putbuf(buf+written, count % 128);
			return count;
		}
		default:
			printf("sys_write not implemented yet!\n")
			exit(-1);
	}
	return -1;
}

static int get_user(const uint8_t* uaddr)
{
	int result;
	asm("movl $1f, %0; movzbl %1, %0; 1:"
			: "=&a" (result) : "m" (*uaddr));
	return result;
}

static bool put_user(uint8_t* udst, uint8_t byte)
{
	int error_code;
	asm("movl $1f, %0; movb %b2, %1; 1:"
			: "=&a" (error_code) : "=m" (*udst) : "q" (byte));
}

static int get_int_32(const void* ptr_)
{
	if (ptr_ % 4 || ptr_ > PHYS_BASE) exit(-1);
	uint8_t *ptr = ptr_;
	int i;
	for (i = 0; i < 4; ++i)
	{
		if (get_user((uint32_t*)(ptr+i)) == -1)
			exit(-1);
	}
	return *((int *)ptr);
}
