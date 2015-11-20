#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
#include "filesys/file.h"

/*
 * shared lock used to protect parent's list of children as a critical section.
 * must be deallocated when count reaches 0 (parent is already dead, no other children exist.
 */
static struct parent_list_guard
{
	struct lock list_lock;
	unsigned count;
	bool parent_alive;
};

/* It's here and not in file.h just because I tried to avoid modification of other parts of the code */
/* fd used to track open by process files */
struct file_descriptor
{
	/*
	 * this structure is dependent on file_sys_lock (belong to syscall.c for now)
	 * any time we change 'file', we should first acquire  lock due to file system limitations
	 */
	int fd;					// file descriptor value
	struct file* file;		// pointer to an open file
	struct list_elem elem;	// element of the list fds in struct process.
};

struct mmap_pid
{
	int mmappid;
	void* addr;
	size_t pg_num;
	struct file* file;
	struct list_elem elem;
};

/*
 * process structure stores all necessary information about process.
 * It is used to track a process state, exit status, children of a process,
 * executable file and open files.
 */
struct process
{
	tid_t pid;				// pid of the process (= tid of the thread it assigned to)
	int exit_status;		// exit status. For parent. Critical section protected by sema wait.
	bool exited;			// true if process exited. Used to avoid racing if child exited before added to the list of children.
	struct list_elem elem; 	// element of parent's children list
	/*
	 * lock used to protect critical section of parent's instance.
	 * Used to avoid racing during child's memory deallocation.
	 */
	struct parent_list_guard* parent_lock;

	struct list children;	// list of child processes
	struct parent_list_guard* my_lock;	// now this process is parent and it has the same lock.

	struct file* executable;	// parent-dependent. must be closed after acquiring parent's lock.
	struct semaphore wait;		// sema is used to wait while child finishes its execution.

	struct list fds;		// this list is not a critical section. No one, except owner, can use it
	struct list mfs;
};
/* initalization */
void process_init(void);

tid_t process_execute (const char *);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

bool install_page (void*, void*, bool);

#endif /* userprog/process.h */
