#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include <bitmap.h>
#include <lib/kernel/console.h>

#include "threads/vaddr.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"

#include "devices/shutdown.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"


#include "vm/page.h"
#include "vm/frame.h"

/* system call functions */
static void syscall_handler (struct intr_frame *);
static void sys_halt(void);
static void sys_exit(int);
static int 	sys_exec(const char*);
static int 	sys_wait(tid_t);
static bool sys_create(const char*, size_t);
static bool sys_remove(const char*);
static int 	sys_open(const char*);
static int 	sys_filesize(int);
static int 	sys_read(unsigned, char*, size_t);
static int 	sys_write(unsigned, const char*, size_t);
static void sys_seek(int, unsigned);
static unsigned sys_tell(int);
static void sys_close(int);
static int 	sys_mmap(int, void*);
static void sys_munmap(int);

/* auxiliary functions */
static struct file_descriptor* find_fd(struct list*, int);
static void munmap(struct mmap_pid*);
static void munmap_all();
static void check_user_buf(char*, size_t, bool);
static void unpin_pages(char*, size_t);
static bool put_user (uint8_t *udst, uint8_t byte);
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
		case SYS_HALT:		sys_halt();
			break;
		case SYS_EXIT: 		sys_exit(get_int_32(f->esp+4));
			break;
		case SYS_EXEC: 		f->eax = sys_exec((const char*)get_int_32(f->esp+4));
			break;
		case SYS_WAIT: 		f->eax = sys_wait((tid_t)get_int_32(f->esp+4));
			break;
		case SYS_CREATE: 	f->eax = sys_create((const char*)get_int_32(f->esp+4), (size_t)get_int_32(f->esp+8));
			break;
		case SYS_REMOVE: 	f->eax = sys_remove((const char*)get_int_32(f->esp+4));
			break;
		case SYS_OPEN: 		f->eax = sys_open((const char*)get_int_32(f->esp+4));
			break;
		case SYS_FILESIZE: 	f->eax = sys_filesize(get_int_32(f->esp+4));
			break;
		case SYS_READ: 		f->eax = sys_read(get_int_32(f->esp+4),
										(char*)get_int_32(f->esp+8),
										get_int_32(f->esp+12));
			break;
		case SYS_WRITE: 	f->eax = sys_write(get_int_32(f->esp+4),
										(const char*)get_int_32(f->esp+8),
										get_int_32(f->esp+12));
			break;
		case SYS_SEEK: 		sys_seek(get_int_32(f->esp+4), (unsigned)get_int_32(f->esp+8));
			break;
		case SYS_TELL: 		f->eax = (unsigned) sys_tell(get_int_32(f->esp+4));
			break;
		case SYS_CLOSE: 	sys_close(get_int_32(f->esp+4));
			break;
		case SYS_MMAP:		f->eax = sys_mmap(get_int_32(f->esp+4), (void*)get_int_32(f->esp+8));
			break;
		case SYS_MUNMAP:	sys_munmap(get_int_32(f->esp+4));
			break;
		default:
		{
			exit(-1);
		}
	}
	thread_current()->esp = NULL;
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
	/* unmap all mappings before exit */
	munmap_all();
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
	check_user_buf(buffer, size, true);
	int ret = -1;
	switch(fd)
	{
		case 0:
		{
			/* if read from console, read it by one char */
			int i = 0;
			for(; i < size; ++i) buffer[i] = input_getc();
			ret = i;
		}
		break;
		case 1: break; // we cannot read from console input
		default:
		{
			/* if we need to read from the file, find the file */
			struct file_descriptor* struct_fd = find_fd(&(thread_current()->proc->fds), fd);
			if(struct_fd)
			{
				// if the file is found, read from it */
				lock_acquire(&file_sys_lock);
				ret = file_read(struct_fd->file, buffer, size);
				lock_release(&file_sys_lock);
			}
		}
	}
	unpin_pages(buffer, size);
	return ret;

}

static int sys_write(unsigned int fd, const char *buffer, size_t size)
{
	/* check validity of a pointer */
	check_user_buf(buffer, size, false);
	int ret = -1;
	switch(fd)
	{
		case 0: break; // cannot write to console output
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

			ret = size;
		}
		break;
		default:
		{
			// if write to file, find fd
			struct file_descriptor* struct_fd = find_fd(&(thread_current()->proc->fds), fd);
			if(struct_fd)
			{
				// if there is such fd, write to the file
				lock_acquire(&file_sys_lock);
				ret = file_write(struct_fd->file, buffer, size);
				lock_release(&file_sys_lock);
			}
		}
	}
	unpin_pages(buffer, size);
	return ret;
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

static int sys_mmap(int fd, void* addr)
{
	/* init unique mmpid */
	static int next_mmpid = 0;
	if (++next_mmpid < 0) next_mmpid = 0;

	/* check correctness of addr */
	if(addr != pg_round_down(addr)) return -1;
	if((unsigned)addr < (unsigned)0x0804800) return -1;

	/* find previously opened file */
	struct file_descriptor* struct_fd = find_fd(&(thread_current()->proc->fds), fd);
	if(!struct_fd) return -1;

	/* check the length of the file. must be greater than 0 */
	lock_acquire(&file_sys_lock);
	int len = file_length(struct_fd->file);
	lock_release(&file_sys_lock);
	if(len <= 0) return -1;

	/* allocate structure and set fields */
	struct mmap_pid* new_mmap = malloc(sizeof(struct mmap_pid));
	if (!new_mmap) return -1;

	new_mmap->file = file_reopen(struct_fd->file);
	new_mmap->pg_num = ((unsigned)len / PGSIZE) + 1;
	new_mmap->addr = addr;
	new_mmap->mmappid = next_mmpid;

	/* check if there is no overlapping */
	size_t i = 0;
	for(; i < new_mmap->pg_num; ++i)
	{
		if (page_lookup(addr + i * PGSIZE))
		{
			free(new_mmap);
			return -1;
		}
	}

	/* create pages for mapping. do not load them */
	size_t ofs = 0;
	for(i = 0; i < new_mmap->pg_num; ++i)
	{
		struct page* new_pg = page_construct(addr + i*PGSIZE, PG_MMAP | PG_WRITABLE);

		size_t page_read_bytes = len < PGSIZE ? len : PGSIZE;

		new_pg->file = new_mmap->file;
		new_pg->ofs = ofs;
		new_pg->read_bytes = page_read_bytes;

		len -= page_read_bytes;
		ofs += page_read_bytes;
	}

	/* add new mapping to the list of mappings and return */
	list_push_back(&thread_current()->proc->mfs, &new_mmap->elem);
	return new_mmap->mmappid;
}


static void sys_munmap(int mapping)
{
	/* traverse list of mappings */
	struct list_elem* e;
	for(e = list_begin(&thread_current()->proc->mfs); e != list_end(&thread_current()->proc->mfs); e = list_next(e))
	{
		/* if mapping is found, unmap it */
		struct mmap_pid* tmp = list_entry(e, struct mmap_pid, elem);
		if (tmp->mmappid == mapping)
		{
			munmap(tmp);
			list_remove(&tmp->elem);
			free(tmp);
			return;
		}
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

/*
 * auxiliary function, which unmaps a given mapping
 */
static void munmap(struct mmap_pid* m)
{
	/* traverse all pages in the mapping */
	size_t i = 0;
	for(; i < m->pg_num; ++i)
	{
		/* find the page */
		struct page* pg = page_lookup(m->addr + i*PGSIZE);
		if(!pg) PANIC("sys_munmap: page not found!");

		/* if page is swapped, bring it back */
		if (swap_check_page(pg))
			page_load(pg);

		/* if the page was modified, write it to the file */
		if (pagedir_is_dirty(thread_current()->pagedir, pg->vaddr))
			file_write_at(m->file, pg->vaddr, pg->read_bytes, pg->ofs);

		/* free memory */
		pagedir_clear_page(thread_current()->pagedir, pg->vaddr);
		hash_delete(thread_current()->pg_table, &pg->elem);
		frame_free(pg->paddr);
		palloc_free_page(pg->paddr);
		free(pg);
	}
	/* close file and remove mapping from the list */
	file_close(m->file);
	return;
}

/*
 * auxiliary function, which unmaps all mappings of the current process. used in sys_exit
 */
static void munmap_all()
{
	struct list_elem* e = list_begin(&thread_current()->proc->mfs);
	while(e != list_end(&thread_current()->proc->mfs))
	{
		struct mmap_pid* tmp = list_entry(e, struct mmap_pid, elem);
		munmap(tmp);

		e = list_remove(&tmp->elem);
		free(tmp);
	}
	return;
}

/*
 * auxiliary function to check user buffer and pin pages
 */
static void check_user_buf(char* buffer, size_t size, bool write)
{
	/* check if the buffer is below kernel memory */
	if(buffer+size-1 >= PHYS_BASE) exit(-1);	
	/* go through all pages covered by buffer */
	char* buf = buffer;
	while((unsigned)buf < (unsigned)buffer + size)
	{
		/*
		 * look up for a page.
		 * if it exists then pin it.
		 * if there is no such page it may be right violation
		 * or stack access. it will be decided during page fault
		 */
		struct page* pg = page_lookup(buf);
		if(pg)
			pg->flags |= PG_PINNED;

		/*
		 * check if we can access buffer.
		 * if page fault occurred than page is brought to memory and pinned
		 */
		if(write)
		{
			if(get_user(buf) == -1 || put_user(buf, *(buf)) == false) exit(-1);
		}
		else
			if(get_user(buf) == -1) exit(-1);
		
		buf = (char*)((unsigned)buf + (unsigned)PGSIZE);
	}

	/* the same, but for the last page */
	buf = (char*)((unsigned)buffer + size);
	struct page* pg = page_lookup(buf);
	if(pg)
		pg->flags |= PG_PINNED;
	if(write)
	{
		if(get_user(buf) == -1 || put_user(buf, *(buf)) == false) exit(-1);
	}
	else
		if(get_user(buf) == -1) exit(-1);
}

/*
 * auxiliary function to unpin all pages used by buffer,
 * since they are no longer in need
 */
static void unpin_pages(char* buffer, size_t size)
{
	char* buf = buffer;
	while((unsigned)buf < (unsigned)buffer + size)
	{
		struct page* pg = page_lookup(buf);
		if(pg)
			pg->flags &= ~PG_PINNED;
		buf = buf + PGSIZE;
	}
	buf = (char*)((unsigned)buffer + size);
	struct page* pg = page_lookup(buf);
	if(pg)
		pg->flags &= ~PG_PINNED;
}

static bool put_user (uint8_t *udst, uint8_t byte)
{
      int error_code;
          asm ("movl $1f, %0; movb %b2, %1; 1:"
                       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
      return error_code != -1;
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
