#include "vm/frame.h"
#include "vm/swap.h"
#include "threads/malloc.h"
#include <list.h>
#include <hash.h>
#include <string.h>
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

static struct frame
{
	struct page* page;		// pointer to the page
	struct list_elem list_elem;	// element of the list of frames
};

static struct list frame_list;		// list to implement second-chance algorithm
static struct lock frame_list_lock;	// lock for the frame list

static struct frame* frames_all;	// array of all frames
static void* base;					// base physical address for user physical memory

static struct frame* frame_evict(void);

/*
 * initializes frame unit.
 * calculates base physical address and allocates array of frames.
 * real number of available frames is smaller, because some pages are used
 * by palloc unit for bit map. No need to worry about the waste of space.
 */
void frame_init(size_t user_page_limit)
{
	/*
	 * this part is taken from palloc.c init(),
	 * because I could not solve dependency resolution of files,
	 * so I decided to just copy calculations.
	 */
	uint8_t *free_start = ptov (1024 * 1024);
	uint8_t *free_end = ptov (init_ram_pages * PGSIZE);
	size_t free_pages = (free_end - free_start) / PGSIZE;
	size_t user_pages = free_pages / 2;
	if (user_pages > user_page_limit)
	  user_pages = user_page_limit;
	size_t kernel_pages = free_pages - user_pages;

	/* initialize variables */
	list_init(&frame_list);
	lock_init(&frame_list_lock);
	frames_all = malloc(user_pages*sizeof(struct frame));

	base = free_start + kernel_pages * PGSIZE;
}

/* allocates a new frame for a page */
void* frame_alloc(struct page* page, enum palloc_flags flags)
{
	ASSERT((flags & PAL_USER) != 0);	// this function is only for users

	struct frame* frame = NULL;
	void* paddr = palloc_get_page(flags);	// try to obtain addr using palloc

	lock_acquire(&frame_list_lock);
	if (!paddr)
	{
		// if no available frames, evict the frame
		frame = frame_evict();										// performs swapping if needed
		size_t frame_idx = ((unsigned)frame - (unsigned)frames_all)/sizeof(struct frame);
		paddr = base + frame_idx * PGSIZE;							// calculate the physical address in the memory
		if (flags & PAL_ZERO) memset (paddr, 0, PGSIZE);			// if needed, set to 0
	}
	else
	{
		// if frame was allocated by palloc, just add it to the list
		size_t frame_idx = ((unsigned)paddr - (unsigned)base)/PGSIZE;
		frame = frames_all + frame_idx;
		list_push_back(&frame_list, &frame->list_elem);
	}
	lock_release(&frame_list_lock);

	// set values
	frame->page = page;
	page->paddr = paddr;
	
	return paddr;	// return physical address of allocated frame
}

/* releases the frame. for now, it is used only when the page table is being destroyed */
void frame_free(void* paddr)
{
	if(!paddr) return;
	size_t frame_idx = ((unsigned)paddr - (unsigned)base)/PGSIZE;

	lock_acquire(&frame_list_lock);

	frames_all[frame_idx].page = NULL;
	list_remove(&frames_all[frame_idx].list_elem);
	//no need to call palloc_free. Frame will be deallocated in pagedir_destroy.

	lock_release(&frame_list_lock);
}

/* evicts a frame using second-chance algorithm */
/* in all tests it works like FIFO ( I checked it during debugging) */
static struct frame* frame_evict(void)
{
	struct frame* evicted_frame = NULL;
	struct list_elem* e = list_begin(&frame_list);
	struct page* candidate_page;
	// while frame is not evicted
	while(!evicted_frame)
	{
		struct frame* candidate_frame = list_entry(e, struct frame, list_elem);
		candidate_page = candidate_frame->page;

		if(!(candidate_page->flags & PG_PINNED))
		{
			// if page is accessed, then don't evict it, but clear the flag and push to the end of the list
			if(pagedir_is_accessed(candidate_page->thread->pagedir, candidate_page->vaddr))
				pagedir_set_accessed(candidate_page->thread->pagedir, candidate_page->vaddr, false);
			else
				evicted_frame = candidate_frame;
		}

		e = list_remove(e);
		list_push_back(&frame_list, &candidate_frame->list_elem);
	}

	// if the page is dirty or it should be swapped, then swap it
	if (pagedir_is_dirty(candidate_page->thread->pagedir, candidate_page->vaddr) || (candidate_page->flags & PG_SWAPPED))
	{
		swap_out(candidate_page);
	}

	/* mark as not in the memory */
	pg->paddr = NULL;

	// remove page from pagedir, so that the next time access will raise exception
	pagedir_clear_page(candidate_page->thread->pagedir, candidate_page->vaddr);
	return evicted_frame;
}
