#include "filesys/cache.h"
#include "vm/page.h"		// flag_t
#include "threads/synch.h"
#include "threads/malloc.h"
#include "devices/timer.h"

#include "string.h"

#define CACHE_SIZE 64

struct cache_block
{
	struct block* block_dev;
	block_sector_t sector;

	flag_t flags;
#define C_ACCD	0x01
#define C_DIRTY	0x02

	uint8_t data[BLOCK_SECTOR_SIZE];

	struct lock lock;

	int64_t last_acc;
};

static struct cache_block cache[CACHE_SIZE];

static int cache_lookup(struct block*, block_sector_t, int);

void cache_init(void)
{
	int i = 0;
	for(; i < CACHE_SIZE; ++i)
	{
		cache[i].block_dev = NULL;
		cache[i].flags = 0;
		lock_init(&cache[i].lock);
		cache[i].last_acc = 0;
	}
}

void cache_read(struct block* block, block_sector_t sector, void* data, off_t offset, int size)
{
//printf("cache_read called block = %p, sector = %u\n", block, sector);
	ASSERT(block != NULL);
	ASSERT(data != NULL);
	ASSERT(offset + size <= BLOCK_SECTOR_SIZE);

	int idx = cache_lookup(block, sector, 1);

	if (idx < 0) PANIC("CACHE LOOKUP FAILED");

	cache[idx].last_acc = timer_ticks();	// reduce probability of waiting during eviction
	memcpy(data, &cache[idx].data + offset, size);

	cache[idx].flags |= C_ACCD;

	lock_release(&cache[idx].lock);
}


void cache_write(struct block* block, block_sector_t sector, void* data, off_t offset, int size)
{
//printf("cache_write called block = %p, sector = %u\n", block, sector);

	ASSERT(block != NULL);
	ASSERT(data != NULL);
	ASSERT(offset + size <= BLOCK_SECTOR_SIZE);

	int idx = cache_lookup(block, sector, 0);

	if (idx < 0) PANIC("CACHE LOOKUP FAILED");

	cache[idx].last_acc = timer_ticks();	// reduce probability of waiting during eviction
	memcpy(&cache[idx].data + offset, data, size);


	cache[idx].flags |= C_ACCD | C_DIRTY;


	lock_release(&cache[idx].lock);
}

static int cache_evict()
{
//printf("cache_evict called\n");
	int ret = -1;
	/* while not evicted. there is a possibility that all blocks are tried to be evicted */
	while (ret < 0)
	{
		int i = 0;
		/* try to evict at least something */
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
			/* if free block is found */
			if (cache[i].block_dev == NULL)
			{
				if(lock_try_acquire(&cache[i].lock))
				{
					/* check again, if it is free */
					if(cache[i].block_dev == NULL)
					{
						/* free, then evict it */
						lock_release(&cache[ret].lock);
						ret = i;
						goto done;
					}
					/* not free, oops */
					lock_release(&cache[i].lock);
				}
			}
			/* check when the block was accessed last time */
			if(cache[i].last_acc < cache[ret].last_acc)
			{
				if(lock_try_acquire(&cache[i].lock))
				{
					/* make sure it is really older */
					if(cache[i].last_acc < cache[ret].last_acc)
					{
						lock_release(&cache[ret].lock);
						ret = i;
					}
					else lock_release(&cache[i].lock); /* not older, release it */
				}
			}
		}
	}

done:
//printf("evicted %i\n", ret);

	if(cache[ret].flags & C_DIRTY)
	{
		//printf("%i is written\n", ret);
		block_write(cache[ret].block_dev, cache[ret].sector, &cache[ret].data);
	}

	return ret;
}

static int cache_lookup(struct block* block, block_sector_t sector, int load)
{
//printf("cache_lookup called\n");
	int i = 0;
	for(; i < CACHE_SIZE; ++i)
	{
		if (cache[i].block_dev == block && cache[i].sector == sector)
		{
			lock_acquire(&cache[i].lock);
			/* make sure that the block was not evicted or something */
			if (cache[i].block_dev == block && cache[i].sector == sector)
				break;
			lock_release(&cache[i].lock);
		}
	}

	if (i == CACHE_SIZE)
	{
		i = cache_evict();
		cache[i].block_dev = block;
		cache[i].sector = sector;
		cache[i].flags = 0;
		if (load)
		{
			block_read(block, sector, &cache[i].data);
		}
	}

	return i;
}
