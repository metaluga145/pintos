#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "hash.h"

#include "threads/thread.h"
#include "filesys/file.h"
#include "threads/palloc.h"

typedef u_char flag_t;

struct page
{
	void* vaddr;
	void* paddr;

	flag_t flags;
#define PG_WRITABLE	0x1
#define PG_FILE		0x2
#define PG_PINNED	0x4

	struct thread* thread;

#define SECTORS_PER_PAGE PGSIZE/BLOCK_SECTOR_SIZE
	size_t swap_idx;

	struct file* file;
	uint32_t read_bytes;
	off_t ofs;

	struct hash_elem elem;
};

struct page_table
{
	struct hash table;
};


struct page_table* page_table_create(void);
void page_table_destroy(struct page_table*);

#endif
