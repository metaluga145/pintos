#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "hash.h"

#include "threads/thread.h"
#include "filesys/file.h"

typedef uint8_t flag_t;

#define MAX_STACK_SIZE (1 << 23)

struct page
{
	void* vaddr;
	void* paddr;

	flag_t flags;
#define PG_WRITABLE	0x1
#define PG_FILE		0x2
#define PG_PINNED	0x4	// I don't see the point when it's needed. I created this, because manual says so. Will remove later, if pass all tests
#define PG_SWAPPED	0x8

	struct thread* thread;

#define SECTORS_PER_PAGE PGSIZE/BLOCK_SECTOR_SIZE
	size_t swap_idx;

	struct file* file;
	uint32_t read_bytes;
	off_t ofs;

	struct hash_elem elem;
};


struct hash* page_table_create(void);
void page_table_destroy(struct hash*);

struct page* page_construct(void*, flag_t);
struct page* page_lookup(void*);
bool page_load(struct page*);
bool page_push_stack(void*);

#endif
