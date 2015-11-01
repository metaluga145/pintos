#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"

#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"

#include <string.h> // memset

/* --------------- page table --------------- */
static unsigned page_hash_func(const struct hash_elem *e, void *aux);
static bool page_cmp (const struct hash_elem *a, const struct hash_elem *b, void *aux);
static void page_destructor(struct hash_elem *e, void *aux);

struct hash* page_table_create(void)
{
	struct hash* newpgt = malloc(sizeof(struct hash));
	hash_init(newpgt, page_hash_func, page_cmp, NULL);

	return newpgt;
}

void page_table_destroy(struct hash* table)
{
	hash_destroy(table, page_destructor);
	free(table);
}

static unsigned page_hash_func(const struct hash_elem *e, void *aux)
{
	struct page* pg = hash_entry(e, struct page, elem);
	return hash_bytes(&pg->vaddr, sizeof(pg->vaddr));
}

static bool page_cmp (const struct hash_elem *a, const struct hash_elem *b, void *aux)
{
	return hash_entry(a, struct page, elem)->vaddr < hash_entry(b, struct page, elem)->vaddr;
}

/* --------------- page --------------- */

struct page* page_construct(void* vaddr, flag_t flags)
{
	ASSERT(vaddr != NULL);

	struct page* new_pg = malloc(sizeof(struct page));
	if(!new_pg) return NULL;

	new_pg->vaddr = vaddr;
	new_pg->paddr = NULL;
	new_pg->flags = flags;
	new_pg->thread = thread_current();
	new_pg->file = NULL;
	new_pg->read_bytes = 0;
	new_pg->ofs = 0;
	hash_insert(new_pg->thread->pg_table, &new_pg->elem);

	return new_pg;
}

bool page_push_stack(void* vaddr)
{
	vaddr = pg_round_down(vaddr);
	if (PHYS_BASE - vaddr > MAX_STACK_SIZE) return false;

	struct page* newpg = page_construct(vaddr, PG_WRITABLE);
	newpg->paddr = frame_alloc(newpg, PAL_USER & PAL_ZERO);

	if(!install_page(newpg->vaddr, newpg->paddr, PG_WRITABLE))
	{
		page_destructor(&newpg->elem, NULL);
		return false;
	}

	return true;
}

struct page* page_lookup(void* vaddr)
{
	struct hash* pg_table = thread_current()->pg_table;
	struct hash_elem* e;
	struct page pg;
	pg.vaddr = pg_round_down(vaddr);
	e = hash_find(pg_table, &pg.elem);

	return e == NULL ? e : hash_entry(e, struct page, elem);
}

bool page_load(struct page* pg)
{
	ASSERT(pg != NULL);

	pg->paddr = frame_alloc(pg, PAL_USER);

	if(pg->flags & PG_FILE)
	{
		if(file_read_at(pg->file, pg->paddr, pg->read_bytes, pg->ofs) != (int)pg->read_bytes)
			goto fail;
		memset(pg->paddr + pg->read_bytes, 0, PGSIZE - pg->read_bytes);
	}
	else swap_in(pg);

	if(!pagedir_set_page(thread_current()->pagedir, pg->vaddr, pg->paddr, pg->flags & PG_WRITABLE))
	goto fail;

	pagedir_set_dirty(thread_current()->pagedir, pg->vaddr, false);
	return true; // page is loaded successfully

	fail:
	frame_free(pg->paddr);
	return false;
}

static void page_destructor(struct hash_elem *e, void *aux)
{
	struct page* page = hash_entry(e, struct page, elem);
	if (page->flags & PG_SWAPPED)
		swap_free(page);
	else frame_free(page->paddr);

	free(page);
}

