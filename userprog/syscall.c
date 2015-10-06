#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <lib/kernel/console.h>
#include <string.h>

#include "userprog/process.h"
#include "threads/vaddr.h"


static void syscall_handler (struct intr_frame *);
static int sys_write(unsigned, const char*, size_t);
static void sys_exit(int);
static int sys_exec(const char*);
static int sys_wait(tid_t);

static int get_user(const uint8_t*);
static int get_int_32(const void*);
static void exit(int code)
{
	sys_exit(code);
}

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
		case SYS_EXIT: sys_exit(get_int_32(f->esp+4));
						NOT_REACHED();
		case SYS_EXEC: f->eax = sys_exec((const char*)get_int_32(f->esp+4));
			break;
		case SYS_WAIT: f->eax = sys_wait((tid_t)get_int_32(f->esp+4));
			break;
		case SYS_WRITE: f->eax = sys_write(get_int_32(f->esp+4),
							(const char*)get_int_32(f->esp+8),
							get_int_32(f->esp+12)); 
			break;
		default:
		{
			exit(-1);
		}
	}
}


static void sys_exit(int code)
{
	printf( "%s: exit(%d)\n", thread_name(), code);
	thread_current()->proc->exit_status = code;
	thread_exit ();
}

static int sys_exec(const char* cmd)
{
	if(cmd >= PHYS_BASE || get_user(cmd) == -1) exit(-1);
	return process_execute(cmd);
}

static int sys_wait(tid_t tid)
{
	return process_wait(tid);
}

static int sys_write(unsigned int fd, const char *buf, size_t count)
{
	if(!buf || buf+count-1 >= PHYS_BASE || get_user(buf) == -1) exit(-1);
	switch(fd)
	{
		case 0: exit(-1);
		case 1:
		{
			size_t written = 0;
			while(written + 128 < count)
			{
				putbuf(buf+written, 128);
				written += 128;
			}
			putbuf(buf+written, count % 128);
			return count;
		}
		default:
			printf("sys_write not implemented yet!\n");
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


static int get_int_32(const void* ptr_)
{
	if ((int)ptr_ % 4 || ptr_ > PHYS_BASE) exit(-1);
	uint8_t *ptr = ptr_;
	int i;
	for (i = 0; i < 4; ++i)
	{
		if (get_user(ptr+i) == -1)
			exit(-1);
	}
	return *((int *)ptr);
}
