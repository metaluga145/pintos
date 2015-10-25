#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "threads/thread.h"

struct page
{
	bool pinned;
	struct thread* thread;
	void* vaddr;
};

#endif
