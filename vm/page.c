#include "vm/page.h"
#include "vm/frame.h"

#include "threads/malloc.h"
#include "threads/palloc.h"

/* --------------- page table --------------- */
static unsigned page_hash_func(const struct hash_elem *e, void *aux);
static bool page_cmp (const struct hash_elem *a, const struct hash_elem *b, void *aux);
static void page_destructor(struct hash_elem *e, void *aux);

struct page_table* page_table_create(void)
{
	struct page_table* newpg = malloc(sizeof(struct page_table));
	hash_init(&newpg->table, page_hash_func, page_cmp, NULL);

	return newpg;
}

void page_table_destroy(struct page_table* table)
{
	hash_destroy(&table->table, page_destructor);
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

struct page* page_construct(void* vaddr, void* paddr,
								struct thread* t, flag_t flags)
{
	ASSERT(vaddr != NULL);
	//ASSERT(paddr != NULL);
	ASSERT(t != NULL);
	ASSERT(t->pg_table != NULL);

	struct page* new_pg = malloc(sizeof(struct page));
	if(!new_pg) return NULL;

	new_pg->vaddr = vaddr;
	new_pg->paddr = paddr;
	new_pg->flags = flags;
	new_pg->thread = t;

	hash_insert(&t->pg_table->table, &new_pg->elem);

	return new_pg;
}

static void page_destructor(struct hash_elem *e, void *aux)
{
	struct page* page = hash_entry(e, struct page, elem);
	/* check if swapped ? */
	frame_free(page->vaddr);

	free(page);
}
