#include "vm/swap.h"
#include "devices/block.h"
#include "bitmap.h"
#include "threads/synch.h"
#include "debug.h"
#include "threads/vaddr.h"
#include <stdio.h>

static struct block* swap_block;
static struct bitmap* swap_table;

static struct lock swap_table_lock;

#define SECTORS_PER_PAGE (PGSIZE/BLOCK_SECTOR_SIZE)

void swap_init(void)
{
	swap_block = block_get_role(BLOCK_SWAP);
	ASSERT(swap_block != NULL);

	swap_table = bitmap_create(block_size(swap_block)/SECTORS_PER_PAGE);
	bitmap_set_all(swap_table, false);

	lock_init(&swap_table_lock);
}

void swap_out(struct page* pg)
{
//printf("page_out called\n");
	ASSERT(pg != NULL);
	ASSERT(pg->paddr != NULL);	// cannot swap out a swapped page!

	lock_acquire(&swap_table_lock);
	size_t idx = bitmap_scan_and_flip(swap_table, 0, 1, false);
	lock_release(&swap_table_lock);

	if (idx == BITMAP_ERROR) PANIC("OUT OF SWAPS! REQUEST CANNOT BE SATISFIED");

	size_t i = 0, swap_base = idx * SECTORS_PER_PAGE;
	for(; i < SECTORS_PER_PAGE; ++i)
		 block_write(swap_block, swap_base + i, (uint8_t*)pg->paddr + (i * BLOCK_SECTOR_SIZE));

printf("page vaddr = %p swapped out from %p to %u, val = %u\n", pg->vaddr, pg->paddr, idx, (*((uint8_t*)pg->paddr)));

	pg->flags |= PG_SWAPPED;
	pg->swap_idx = idx;
}

void swap_in(struct page* pg)
{
//printf("page_in called\n");
	ASSERT(pg != NULL);
	ASSERT(pg->paddr != NULL);	// frame must be allocated
	ASSERT(pg->swap_idx != BITMAP_ERROR);
	ASSERT(bitmap_test(swap_table, pg->swap_idx));	// page must be swapped out

	size_t i = 0, swap_base = pg->swap_idx * SECTORS_PER_PAGE;
	for(; i < SECTORS_PER_PAGE; ++i)
		 block_read(swap_block, swap_base + i, (uint8_t*)pg->paddr + (i * BLOCK_SECTOR_SIZE));

	lock_acquire(&swap_table_lock);
	bitmap_set(swap_table, pg->swap_idx, false);
	lock_release(&swap_table_lock);
printf("page vaddr = %p swapped in from %u to %p, val = %u\n",pg->vaddr, pg->swap_idx, pg->paddr, (*((uint8_t*)pg->paddr)));
	pg->swap_idx = BITMAP_ERROR;
}

void swap_free(struct page* pg)
{
//printf("swap freed %u\n", pg->swap_idx);
	lock_acquire(&swap_table_lock);
	bitmap_set(swap_table, pg->swap_idx, false);
	lock_release(&swap_table_lock);
}
