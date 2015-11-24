#include "vm/swap.h"
#include "devices/block.h"
#include "bitmap.h"
#include "threads/synch.h"
#include "debug.h"
#include "threads/vaddr.h"
#include <stdio.h>

static struct block* swap_block;	// block for swapping
static struct bitmap* swap_table;	// indicates used and free slots for swapping

static struct lock swap_table_lock;	// lock to protect the table

#define SECTORS_PER_PAGE (PGSIZE/BLOCK_SECTOR_SIZE)	// number of sectors per page

/* initialize swap unit */
void swap_init(void)
{
	swap_block = block_get_role(BLOCK_SWAP);	// get swap partition or block
	ASSERT(swap_block != NULL);

	swap_table = bitmap_create(block_size(swap_block)/SECTORS_PER_PAGE);	// create a swap table
	bitmap_set_all(swap_table, false);			// initialize a swap table

	lock_init(&swap_table_lock);				// init lock
}

/* swaps the page pg to a swap block. page must be pinned */
void swap_out(struct page* pg)
{
	ASSERT(pg != NULL);
	ASSERT(pg->paddr != NULL);	// cannot swap out a swapped page!

	/* find a free swap place on the block */
	lock_acquire(&swap_table_lock);
	size_t idx = bitmap_scan_and_flip(swap_table, 0, 1, false);

	if (idx == BITMAP_ERROR) PANIC("OUT OF SWAPS! REQUEST CANNOT BE SATISFIED");

	/* perform writing */
	size_t i = 0, swap_base = idx * SECTORS_PER_PAGE;
	for(; i < SECTORS_PER_PAGE; ++i)
		 block_write(swap_block, swap_base + i, (uint8_t*)pg->paddr + (i * BLOCK_SECTOR_SIZE));

	pg->flags |= PG_SWAPPED;	// page must be swapped next time when it's evicted
	pg->swap_idx = idx;		// save swap index

	lock_release(&swap_table_lock);
}

/* loads a page pg from the swap. page must be pinned */
void swap_in(struct page* pg)
{
	ASSERT(pg != NULL);
	ASSERT(pg->paddr != NULL);	// frame must be allocated
	ASSERT(pg->swap_idx != BITMAP_ERROR);
	ASSERT(bitmap_test(swap_table, pg->swap_idx));	// page must be swapped out

	/* perform reading to the memory */
	size_t i = 0, swap_base = pg->swap_idx * SECTORS_PER_PAGE;
	for(; i < SECTORS_PER_PAGE; ++i)
		 block_read(swap_block, swap_base + i, (uint8_t*)pg->paddr + (i * BLOCK_SECTOR_SIZE));

	// free swap slot
	lock_acquire(&swap_table_lock);
	bitmap_set(swap_table, pg->swap_idx, false);
	lock_release(&swap_table_lock);

	// mark page as not swapped
	pg->swap_idx = BITMAP_ERROR;
}

/* frees swap slot. used in destroying page tables */
void swap_free(struct page* pg)
{
	lock_acquire(&swap_table_lock);
	bitmap_set(swap_table, pg->swap_idx, false);
	lock_release(&swap_table_lock);
}

/* check if page is swapped or not */
int swap_check_page(struct page* pg)
{
	/*
	 * page may be was evicted just recently or before,
	 * we need to make sure that the swapping is finished before we check it
	 */
	int ret = 0;
	lock_acquire(&swap_table_lock);
	ret = (pg->swap_idx != BITMAP_ERROR);
	lock_release(&swap_table_lock);
	return ret;
}
