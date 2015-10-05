#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"

struct process
{
	int pid;
	int exit_status;
	struct thread* pthread;
	struct list children;
	struct list_elem elem; 	// element of parent's children list
	struct lock list_lock;

	struct semaphore wait;
};

tid_t process_execute (const char *);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
