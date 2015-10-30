#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include <hash.h>
#include "threads/synch.h"
#include "vm/page.h"

static struct frame
{
	struct page* page;		// pointer to the page
	struct list_elem list_elem;	// element of the list of frames
};

static struct list frame_list;
static struct lock frame_list_lock;

static struct frame* frames_all;
static void* base;


void frame_init(unsigned num_frames, void* base_);
void* frame_alloc(struct page *, enum palloc_flags);
void frame_free(void*);

#endif
