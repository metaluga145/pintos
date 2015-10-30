#include "vm/frame.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
static struct frame* frame_evict(void);

void frame_init(unsigned num_frames, void* base_)
{
	list_init(&frame_list);
	frames_all = malloc(num_frames*sizeof(struct frame));
	lock_init(&frame_list_lock);

	base = base_;
}

void* frame_alloc(struct page *, enum palloc_flags flags)
{
	ASSERT(flags & PAL_USER != 0);		// this function is only for users

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

	while(!evicted_frame)
	{
		struct frame* candidate_frame = list_entry(e, struct frame, list_elem);
		struct page* candidate_page = frame->page;

		if(!(candidate_page->pinned))
		{
			if(pagedir_is_accessed(candidate_page->thread->pagedir, candidate_page->vaddr))
				pagedir_set_accessed(candidate_page->thread->pagedir, candidate_page->vaddr, false);
			else
				evicted_frame = candidate_frame;
		}

		e = list_remove(e);
		list_push_back(&frame_list, &candidate_frame->list_elem);
	}

	if (pagedir_is_dirty(evicted_frame->thread->pagedir, evicted_frame->vaddr))
	{
		//swap 	out
	}
	return evicted_frame;
}
