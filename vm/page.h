#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "hash.h"

#include "threads/thread.h"
#include "filesys/file.h"

typedef uint8_t flag_t;	// type of flags

#define MAX_STACK_SIZE (1 << 23)	// define maximum stack size of 8 MB

struct page
{
	void* vaddr;		// virtual address of the page
	void* paddr;		// physical address of the page

	flag_t flags;		// page flags
#define PG_WRITABLE	0x1	// set if page is writable
#define PG_FILE		0x2	// set if page is loaded from file (not set if page is on the stack)
#define PG_PINNED	0x4	// set if page is pinned. For now used to load files (not for system calls).
#define PG_SWAPPED	0x8	// set if page should be swapped during eviction

	struct thread* thread;	// pointer to the thread-owner

//#define SECTORS_PER_PAGE PGSIZE/BLOCK_SECTOR_SIZE	// circular dependency resolution.
	size_t swap_idx;	// index of the page on the swap partition

	struct file* file;	//if page is from file, then assigned as a pointer to a file
	uint32_t read_bytes;// number of bytes to read from file
	//uint32_t zero_bytes;
	off_t ofs;			// offset in the file

	struct hash_elem elem;	// element of the page table;
};


struct hash* page_table_create(void);
void page_table_destroy(struct hash*);

struct page* page_construct(void*, flag_t);
void page_destructor(struct hash_elem *e, void *aux);
struct page* page_lookup(void*);
bool page_load(struct page*);
bool page_push_stack(void*);

#endif
