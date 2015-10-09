#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
#include "filesys/file.h"

static struct parent_list_guard
{
	struct lock list_lock;
	unsigned count;
	bool parent_alive;
};

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

struct process
{
	tid_t pid;
	int exit_status;
	bool exited;
	struct list_elem elem; 	// element of parent's children list
	struct parent_list_guard* parent_lock;

	struct list children;
	struct parent_list_guard* my_lock;

	struct file* executable;	// parent-dependent. must be closed after acquiring parent's lock
	struct semaphore wait;

	struct list fds;		// this list is not a critical section. No one, except owner, can use it
};

void process_init(void);

tid_t process_execute (const char *);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
