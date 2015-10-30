#include "vm/page.h"
#include "vm/frame.h"

#include "threads/malloc.h"
#include "threads/palloc.h"

/* --------------- page table --------------- */
static hash_hash_func page_hash_func;
static hash_less_func page_cmp;
static hash_action_funct page_destructor;

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

static hash_hash_func page_hash_func
{
	struct page* page = hash_entry(e, struct page, elem);
	return hash_bytes(&p->vaddr, sizeof(p->vaddr));
}

static hash_less_func page_cmp
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

static hash_action_funct page_destructor
{
	struct page* page = hash_entry(e, struct page, elem);
	/* check if swapped ? */
	frame_free(page->vaddr);

	free(page);
}
