#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/synch.h"
#include "vm/page.h"
#include "threads/palloc.h"

void frame_init(size_t user_page_limit);
void* frame_alloc(struct page *, enum palloc_flags);
void frame_free(void*);

#endif
