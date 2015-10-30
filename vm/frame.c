#include "vm/frame.h"
#include "threads/malloc.h"
#include <list.h>
#include <hash.h>
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

static struct frame
{
	struct page* page;		// pointer to the page
	struct list_elem list_elem;	// element of the list of frames
};

static struct list frame_list;
static struct lock frame_list_lock;

static struct frame* frames_all;
static void* base;

static struct frame* frame_evict(void);

void frame_init(size_t user_page_limit)
{
	uint8_t *free_start = ptov (1024 * 1024);
	uint8_t *free_end = ptov (init_ram_pages * PGSIZE);
	size_t free_pages = (free_end - free_start) / PGSIZE;
	size_t user_pages = free_pages / 2;
	if (user_pages > user_page_limit)
	  user_pages = user_page_limit;
	size_t kernel_pages = free_pages - user_pages;

	list_init(&frame_list);
	frames_all = malloc(user_pages*sizeof(struct frame));
	lock_init(&frame_list_lock);

	base = free_start + kernel_pages * PGSIZE;
}

void* frame_alloc(struct page* page, enum palloc_flags flags)
{
	ASSERT((flags & PAL_USER) != 0);		// this function is only for users

	struct frame* frame = NULL;
	void* paddr = palloc_get_page(flags);

	lock_acquire(&frame_list_lock);
	if (!paddr)
	{
		frame = frame_evict();			// performs swapping if needed
		size_t frame_idx = (frame - frames_all)/sizeof(struct frame);
		paddr = base + frame_idx * PGSIZE;
	}
	else
	{
		size_t frame_idx = (paddr - base)/PGSIZE;
		frame = &frames_all[frame_idx];
		list_push_back(&frame_list, &frame->list_elem);
	}

	frame->page = page;

	lock_release(&frame_list_lock);

	return paddr;
}

void frame_free(void* addr)
{
	size_t frame_idx = (addr - base)/PGSIZE;

	lock_acquire(&frame_list_lock);

	frames_all[frame_idx].page = NULL;
	list_remove(&frames_all[frame_idx].list_elem);
	palloc_free_page(addr);

	lock_release(&frame_list_lock);
}

static struct frame* frame_evict(void)
{
	struct frame* evicted_frame = NULL;
	struct list_elem* e = list_begin(&frame_list);
	struct page* candidate_page;

	while(!evicted_frame)
	{
		struct frame* candidate_frame = list_entry(e, struct frame, list_elem);
		candidate_page = candidate_frame->page;

		if(!(candidate_page->flags & PG_PINNED))
		{
			if(pagedir_is_accessed(candidate_page->thread->pagedir, candidate_page->vaddr))
				pagedir_set_accessed(candidate_page->thread->pagedir, candidate_page->vaddr, false);
			else
				evicted_frame = candidate_frame;
		}

		e = list_remove(e);
		list_push_back(&frame_list, &candidate_frame->list_elem);
	}

	if (pagedir_is_dirty(candidate_page->thread->pagedir, candidate_page->vaddr))
	{
		//swap 	out
	}
	return evicted_frame;
}
