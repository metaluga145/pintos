#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <lib/kernel/console.h>
#include <string.h>
#include "threads/malloc.h"

#include "devices/shutdown.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/vaddr.h"

/* system call functions */
static void syscall_handler (struct intr_frame *);
static void sys_halt(void);
static void sys_exit(int);
static int sys_exec(const char*);
static int sys_wait(tid_t);
static bool sys_create(const char*, size_t);
static bool sys_remove(const char*);
static int sys_open(const char*);
static int sys_filesize(int);
static int sys_read(unsigned, char*, size_t);
static int sys_write(unsigned, const char*, size_t);
static void sys_seek(int, unsigned);
static unsigned sys_tell(int);
static void sys_close(int);

/* auxiliary functions */
static struct file_descriptor* find_fd(struct list*, int);
static int get_user(const uint8_t*);
static int get_int_32(const void*);
void exit(int code)
{
	sys_exit(code);
}

/* lock is used to make sure that only one process is writing to the file at a time */
static struct lock file_sys_lock;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_sys_lock);
}

static void
syscall_handler (struct intr_frame *f)
{
	/*
	 * get the system call number and get all appropriate arguments.
	 * type conversion is not preserved in several places, so there might be warnings about it.
	 */
	thread_current()->esp = f->esp; /* transition from user mode to kernel mode */

	int syscalln = get_int_32(f->esp);
	switch(syscalln)
	{
		case SYS_HALT:	sys_halt();
			break;
		case SYS_EXIT: sys_exit(get_int_32(f->esp+4));
			break;
		case SYS_EXEC: f->eax = sys_exec((const char*)get_int_32(f->esp+4));
			break;
		case SYS_WAIT: f->eax = sys_wait((tid_t)get_int_32(f->esp+4));
			break;
		case SYS_CREATE: f->eax = sys_create((const char*)get_int_32(f->esp+4), (size_t)get_int_32(f->esp+8));
			break;
		case SYS_REMOVE: f->eax = sys_remove((const char*)get_int_32(f->esp+4));
			break;
		case SYS_OPEN: f->eax = sys_open((const char*)get_int_32(f->esp+4));
			break;
		case SYS_FILESIZE: f->eax = sys_filesize(get_int_32(f->esp+4));
			break;
		case SYS_READ: f->eax = sys_read(get_int_32(f->esp+4),
									(char*)get_int_32(f->esp+8),
									get_int_32(f->esp+12));
			break;
		case SYS_WRITE: f->eax = sys_write(get_int_32(f->esp+4),
								(const char*)get_int_32(f->esp+8),
								get_int_32(f->esp+12));
			break;
		case SYS_SEEK: sys_seek(get_int_32(f->esp+4), (unsigned)get_int_32(f->esp+8));
			break;
		case SYS_TELL: f->eax = (unsigned) sys_tell(get_int_32(f->esp+4));
			break;
		case SYS_CLOSE: sys_close(get_int_32(f->esp+4));
			break;
		default:
		{
			exit(-1);
		}
	}
}


static void sys_halt(void)
{
	shutdown_power_off();
	NOT_REACHED();
}

static void sys_exit(int code)
{
	printf( "%s: exit(%d)\n", thread_name(), code);
	thread_current()->proc->exit_status = code;
	/*
	 * currently all files must be closed here due to limitations of file system
	 * in the future, we should move this section to process_exit function
	 */
	// ----------------------------------------------
	struct file_descriptor* fd;
	struct list_elem* e;
	for(e = list_begin(&thread_current()->proc->fds);
			e != list_end(&thread_current()->proc->fds);)
	{
		fd = list_entry(e, struct file_descriptor, elem);
		e = list_remove(e);
		file_close(fd->file);
		free(fd);
	}
	// ----------------------------------------------
	thread_exit ();
	NOT_REACHED ();
}

static int sys_exec(const char* cmd)
{
	/* check validity of a pointer and execute the command */
	if(cmd >= PHYS_BASE || get_user(cmd) == -1) exit(-1);
	return process_execute(cmd);
}

static int sys_wait(tid_t tid)
{
	/* just call process_wait, everything is done there */
	return process_wait(tid);
}

static bool sys_create(const char* file_name, size_t init_size)
{
	/* check validity of a pointer */
	if (file_name >= PHYS_BASE || get_user(file_name) == -1) exit(-1);
	/* acquire lock and try to create a file. return result */
	bool ret;
	lock_acquire(&file_sys_lock);
	ret = filesys_create(file_name, init_size);
	lock_release(&file_sys_lock);
	return ret;
}


static bool sys_remove(const char* file_name)
{
	/* check validity of a pointer */
	if (file_name >= PHYS_BASE || get_user(file_name) == -1) exit(-1);
	/* acquire lock and try to remove a file. return result */
	bool ret;
	lock_acquire(&file_sys_lock);
	ret = filesys_remove(file_name);
	lock_release(&file_sys_lock);
	return ret;
}

static int sys_open(const char* file_name)
{
	/* check validity of a pointer */
	if (file_name >= PHYS_BASE || get_user(file_name) == -1) exit(-1);
	/* calculate next value of fd */
	static int next_fd;
	if (next_fd < 2) next_fd = 2;
	/* acquire lock and try to open a file. return result */
	int ret = -1;
	struct file* file;
	lock_acquire(&file_sys_lock);
	file = filesys_open(file_name);
	lock_release(&file_sys_lock);

	if(file)
	{
		/* if file is opened, store file descriptor to the list of descriptors */
		struct file_descriptor* fd= malloc(sizeof(struct file_descriptor));
		fd->fd = next_fd++;
		fd->file = file;
		list_push_back(&(thread_current()->proc->fds), &fd->elem);
		ret = fd->fd; 	// we cannot use next_fd, because it's in critical section
	}

	return ret;
}

static int sys_filesize(int fd)
{
	/*
	 * try to find fd in the list of fds, which belong to current process
	 * no need to acquire a lock, because no data racing in this list.
	 * only holder can access this list
	 */
	struct file_descriptor* struct_fd = find_fd(&(thread_current()->proc->fds), fd);

	int ret = -1;
	if (struct_fd)
	{
		// if there is such fd, return the length of the file.
		lock_acquire(&file_sys_lock);
		ret = file_length(struct_fd->file);
		lock_release(&file_sys_lock);
	}
	return ret;
}

static int sys_read(unsigned fd, char* buffer, size_t size)
{
	/* check validity of a pointer */
	if (buffer+size-1 >= PHYS_BASE || get_user(buffer) == -1) exit(-1);
	switch(fd)
	{
		case 0:
		{
			/* if read from console, read it by one char */
			int i = 0;
			for(; i < size; ++i) buffer[i] = input_getc();
			return i;
		}
		case 1: return -1; // we cannot read from console input
		default:
		{
			/* if we need to read from the file, find the file */
			struct file_descriptor* struct_fd = find_fd(&(thread_current()->proc->fds), fd);
			int ret = -1;
			if(struct_fd)
			{
				// if the file is found, read from it */
				lock_acquire(&file_sys_lock);
				ret = file_read(struct_fd->file, buffer, size);
				lock_release(&file_sys_lock);
			}
			return ret;
		}
	}
	return -1;

}

static int sys_write(unsigned int fd, const char *buffer, size_t size)
{
	/* check validity of a pointer */
	if(buffer+size-1 >= PHYS_BASE || get_user(buffer) == -1) exit(-1);
	switch(fd)
	{
		case 0: return -1; // cannot write to console output
		case 1:
		{
			// if write to console, split in chunks and write to console
			size_t written = 0;
			while(written + 128 < size)
			{
				putbuf(buffer+written, 128);
				written += 128;
			}
			putbuf(buffer+written, size % 128);
			return size;
		}
		default:
		{
			// if write to file, find fd
			struct file_descriptor* struct_fd = find_fd(&(thread_current()->proc->fds), fd);
			int ret = -1;
			if(struct_fd)
			{
				// if there is such fd, write to the file
				lock_acquire(&file_sys_lock);
				ret = file_write(struct_fd->file, buffer, size);
				lock_release(&file_sys_lock);
			}
			return ret;
		}
	}
	return -1;
}

static void sys_seek(int fd, unsigned position)
{
	/* find such fd */
	struct file_descriptor* struct_fd = find_fd(&(thread_current()->proc->fds), fd);
	if(struct_fd)
	{
		// if found, seek
		lock_acquire(&file_sys_lock);
		file_seek(struct_fd->file, position);
		lock_release(&file_sys_lock);
	}
}


static unsigned sys_tell(int fd)
{
	/* find such fd */
	struct file_descriptor* struct_fd = find_fd(&(thread_current()->proc->fds), fd);
	unsigned ret = 0;
	if(struct_fd)
	{
		// if found, tell
		lock_acquire(&file_sys_lock);
		ret = file_tell(struct_fd->file);
		lock_release(&file_sys_lock);
	}
	return ret;
}

static void sys_close(int fd)
{
	/* find such fd */
	struct file_descriptor* struct_fd = find_fd(&(thread_current()->proc->fds), fd);
	if(struct_fd)
	{
		// if found, close it, remove from the list and deallocate the structure
		lock_acquire(&file_sys_lock);
		file_close(struct_fd->file);
		lock_release(&file_sys_lock);

		list_remove(&struct_fd->elem);
		free(struct_fd);
	}
}

/*
 * auxiliary function, find file associated with a given file descriptor.
 * returns NULL, if not such fd in the list.
 */
static struct file_descriptor* find_fd(struct list* fds, int fd)
{
	struct file_descriptor* ret = NULL;
	struct list_elem* e;
	for(e = list_begin(fds);
			e != list_end(fds);
			e = list_next(e))
	{
		struct file_descriptor* tmp = list_entry(e, struct file_descriptor, elem);
		if (tmp->fd == fd)
		{
			ret = tmp;
			break;
		}
	}

	return ret;
}
/* get user to check validity of the pointer */
static int get_user(const uint8_t* uaddr)
{
	int result;
	asm("movl $1f, %0; movzbl %1, %0; 1:"
			: "=&a" (result) : "m" (*uaddr));
	return result;
}

/*
 * auxiliary function, used to get 4 bytes stored on ptr_,
 * checking if all of them belong to the user.
 */
static int get_int_32(const void* ptr_)
{
	if (ptr_ >= PHYS_BASE) exit(-1);
	uint8_t *ptr = ptr_;
	int i;
	for (i = 0; i < 4; ++i)
	{
		if (get_user(ptr+i) == -1)
			exit(-1);
	}
	return *((int *)ptr);
}
