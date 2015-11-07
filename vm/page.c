#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"

#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"

#include <string.h> // memset
#include "bitmap.h"

/* --------------- page table --------------- */
static unsigned page_hash_func(const struct hash_elem *e, void *aux);
static bool page_cmp (const struct hash_elem *a, const struct hash_elem *b, void *aux);

/* creates a page table for each process */
struct hash* page_table_create(void)
{
	struct hash* newpgt = malloc(sizeof(struct hash));
	hash_init(newpgt, page_hash_func, page_cmp, NULL);

	return newpgt;
}

/*
 * destroys a given page table.
 * all resources are freed if needed
 */
void page_table_destroy(struct hash* table)
{
	if(table)
	{
		hash_destroy(table, page_destructor);
		free(table);
	}
}

/* hash function for page table. uses internal hash function from library */
static unsigned page_hash_func(const struct hash_elem *e, void *aux)
{
	struct page* pg = hash_entry(e, struct page, elem);
	return hash_bytes(&pg->vaddr, sizeof(pg->vaddr));
}

/* compares two pages by their vaddr fields */
static bool page_cmp (const struct hash_elem *a, const struct hash_elem *b, void *aux)
{
	return hash_entry(a, struct page, elem)->vaddr < hash_entry(b, struct page, elem)->vaddr;
}

/* --------------- page --------------- */

/* constructs a new instance of the page */
struct page* page_construct(void* vaddr, flag_t flags)
{
	/* page cannot be allocated at virtual addr == NULL */
	ASSERT(vaddr != NULL);

	struct page* new_pg = malloc(sizeof(struct page));
	if(!new_pg) return NULL;

	/* set fields */
	new_pg->vaddr = vaddr;
	new_pg->paddr = NULL;
	new_pg->flags = flags;
	new_pg->thread = thread_current();
	new_pg->swap_idx = BITMAP_ERROR;
	new_pg->file = NULL;
	new_pg->read_bytes = 0;
	new_pg->ofs = 0;
	/* add page to a page table */
	hash_insert(new_pg->thread->pg_table, &new_pg->elem);

	return new_pg;
}

/*
 * adds one page to the top of stack.
 * used in proccess.c and exception.c
 */
bool page_push_stack(void* vaddr)
{
	vaddr = pg_round_down(vaddr);	// calculate page vaddr
	if ((unsigned)PHYS_BASE - (unsigned)vaddr > (unsigned)MAX_STACK_SIZE) return false;	// check if stack has not reached it's maximum size
	struct page* newpg = page_construct(vaddr, PG_WRITABLE | PG_SWAPPED);	// create a new page
	newpg->paddr = frame_alloc(newpg, PAL_USER | PAL_ZERO);					// allocate frame for the page

	if(!install_page(newpg->vaddr, newpg->paddr, PG_WRITABLE))				// install new page
	{
		page_destructor(&newpg->elem, NULL);
		return false;
	}

	return true;
}

/*
 * finds a page given virtual address.
 * returns NULL if no such page.
 */
struct page* page_lookup(void* vaddr)
{
	struct hash* pg_table = thread_current()->pg_table;
	struct hash_elem* e;
	struct page pg;
	pg.vaddr = pg_round_down(vaddr);
	e = hash_find(pg_table, &pg.elem);

	return e == NULL ? e : hash_entry(e, struct page, elem);
}

/*
 * loads page into the memory.
 * frame is allocated here.
 */
bool page_load(struct page* pg)
{
	ASSERT(pg != NULL);

	pg->flags |= PG_PINNED; // pin page for reading

	pg->paddr = frame_alloc(pg, PAL_USER);

	if(pg->swap_idx != BITMAP_ERROR) swap_in(pg);
	else if(pg->flags & PG_FILE)
	{
		if(file_read_at(pg->file, pg->paddr, pg->read_bytes, pg->ofs) != (int)pg->read_bytes)
			goto fail;
		memset((uint8_t*)pg->paddr + pg->read_bytes, 0, PGSIZE - pg->read_bytes);
	}
	else NOT_REACHED();

	page->flags &= ~PG_PINNED;	// unpin page after it's read

	if(!install_page(pg->vaddr, pg->paddr, pg->flags & PG_WRITABLE))
	goto fail;

	return true; // page is loaded successfully

	fail:
	frame_free(pg->paddr);
	return false;
}

/*
 * destroys a page and frees resources, given a hash element of the page.
 * also is used for destroying page table.
 */
void page_destructor(struct hash_elem *e, void *aux)
{
	struct page* page = hash_entry(e, struct page, elem);
	if (page->swap_idx != BITMAP_ERROR)
		swap_free(page);
	else frame_free(page->paddr);

	free(page);
}

