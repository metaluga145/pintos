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
};

void process_init(void);

tid_t process_execute (const char *);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
