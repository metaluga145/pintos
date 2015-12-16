#include "filesys/cache.h"
#include "vm/page.h"		// flag_t
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/interrupt.h"
#include "devices/timer.h"

#include "string.h"

/* definition of the cache size */
#define CACHE_SIZE 64

/*
 * an element of the cache
 */
struct cache_block
{
	/* which block and from which device is cached */
	struct block* block_dev;
	block_sector_t sector;

	/* flags? not used? need to remove? */
	flag_t flags;
#define C_ACCD	0x01
#define C_DIRTY	0x02

	/* actual data in the block */
	uint8_t data[BLOCK_SECTOR_SIZE];
	/* lock for the current block. locked, when data is read or written */
	struct lock lock;
	/* time of the last access. LRU */
	int64_t last_acc;
};

/* array of cached blocks */
static struct cache_block cache[CACHE_SIZE];
/* global lock. used for searching and eviction */
static struct lock cache_lock;
static int cache_lookup(struct block*, block_sector_t, int);

void cache_init(void)
{
	lock_init(&cache_lock);
	int i = 0;
	for(; i < CACHE_SIZE; ++i)
	{
		cache[i].block_dev = NULL;
		cache[i].flags = 0;
		lock_init(&cache[i].lock);
		cache[i].last_acc = 0;
	}
}

/*
 * reads size bytes of data from the given block at offset.
 */
void cache_read(struct block* block, block_sector_t sector, void* data, unsigned offset, int size)
{
//printf("cache_read called block = %p, sector = %u\n", block, sector);
	ASSERT(block != NULL);
	ASSERT(data != NULL);
	ASSERT(offset + size <= BLOCK_SECTOR_SIZE);
	/*
	 * find block. if there is no such block,
	 * evict and store. returns block,
	 * the lock is acquired already.
	 */
	int idx = cache_lookup(block, sector, 1);

	if (idx < 0) PANIC("CACHE LOOKUP FAILED");

	cache[idx].last_acc = timer_ticks();	// store time of the last access

	/* I hate those bugs with data type conversions */
	uint8_t* addr = (uint8_t*)((unsigned)(&cache[idx].data) + offset);
	memcpy(data, addr, size);	// read data

	cache[idx].flags |= C_ACCD;		// set access flag

	lock_release(&cache[idx].lock);	// release lock
}

/*
 * writes size bytes of data from the given block at offset.
 */
void cache_write(struct block* block, block_sector_t sector, void* data, unsigned offset, int size)
{
//printf("cache_write called block = %p, sector = %u\n", block, sector);

	ASSERT(block != NULL);
	ASSERT(data != NULL);
	ASSERT(offset + size <= BLOCK_SECTOR_SIZE);

	/* the function is the same as cache_read. just we store data, rather than read it */
	int idx = cache_lookup(block, sector, 0);

	if (idx < 0) PANIC("CACHE LOOKUP FAILED");

	cache[idx].last_acc = timer_ticks();	// reduce probability of waiting during eviction

	/* I hate those bugs with data type conversions */
	uint8_t* addr = (uint8_t*)((unsigned)(&cache[idx].data) + offset);
	memcpy(addr, data, size);

	cache[idx].flags |= C_ACCD | C_DIRTY;


	lock_release(&cache[idx].lock);
}

/*
 * flushes cache to disk. used in shutting down
 */
void cache_flush(void)
{
	int i = 0;
	for(; i < CACHE_SIZE; ++i)
	{
		if (cache[i].flags & C_DIRTY)
		{
			block_write(cache[i].block_dev, cache[i].sector, &cache[i].data);
		}
	}
}

/*
 * eviction of the cache block.
 * pure LRU based on the time of the last access.
 * here I assume that if lock cannot be acquired,
 * then the block is accessed now, so it access time is relatively great,
 * or it is already evicted.
 */
static int cache_evict()
{
//printf("cache_evict called\n");
	int ret = -1;
	/* while not evicted. there is a possibility that all blocks are tried to be evicted */
	while (ret < 0)
	{
		int i = 0;
		/* try to evict at least one block, which can be evicted (not used at that moment) */
		for(; i < CACHE_SIZE; ++i)
		{
			if(lock_try_acquire(&cache[i].lock))
			{
				ret = i;	/* evicted for now */
				if(cache[i].block_dev == NULL)
					goto done;
				break;
			}
		}
		++i;	// advance
		/* all before were accessed. try to find older block */
		for(; i < CACHE_SIZE; ++i)
		{
			if(lock_try_acquire(&cache[i].lock))
			{
				/* check again, if it is free */
				if(cache[i].block_dev == NULL)
				{
					/* release previously evicted */
					lock_release(&cache[ret].lock);
					ret = i;
					goto done;
				}else
				if(cache[i].last_acc < cache[ret].last_acc)
				{
					/* release previously evicted */
					lock_release(&cache[ret].lock);
					ret = i;
				} else
				lock_release(&cache[i].lock);
			}
		}
	}

done:
//printf("evicted %i\n", ret);
	return ret;
}

/*
 * finds given block in the cache.
 * if there is no such block, brings it from the disk
 */
static int cache_lookup(struct block* block, block_sector_t sector, int load)
{
//printf("cache_lookup called\n");
	int i = 0;
	/* acquire global lock and try to find */
	lock_acquire(&cache_lock);
	for(; i < CACHE_SIZE; ++i)
	{
		if (cache[i].block_dev == block && cache[i].sector == sector)
			break;
	}

	/* if no such block in cache */
	if (i == CACHE_SIZE)
	{
		/* evict the block */
		i = cache_evict();
//printf("evicted %i\n", i);

		/* store old values */
		struct block* old_block = cache[i].block_dev;
		block_sector_t old_sector = cache[i].sector;
		int dirty = cache[i].flags & C_DIRTY;

		/* set up new values */
		cache[i].block_dev = block;
		cache[i].sector = sector;
		cache[i].flags = 0;

		/* write if dirty */
		if(dirty)
		{
			//printf("%i is written\n", i);
			block_write(old_block, old_sector, &cache[i].data);
		}
		/* release gloval lock */
		lock_release(&cache_lock);
		/* read data, so we do not have to wait for I/O here */
		block_read(block, sector, &cache[i].data);

	}
	else
	{
//printf("found %i\n", i);
		/* make sure that we will acquire this lock before any other thread will evict it */
		intr_disable();
		lock_release(&cache_lock);
		lock_acquire(&cache[i].lock);
		intr_enable();
	}

	return i;
}
