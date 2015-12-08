#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/cache.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define NDIRECT		(int)124
#define NINDIRECT	(int)128
#define NDINDIRECT	(int)128*128
/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    block_sector_t blocks[126];         /* Sectors. */
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
  };

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  if (pos < inode->data.length)
  {
	  block_sector_t sec_num = pos / BLOCK_SECTOR_SIZE;
	  if(sec_num < 124) return inode->data.blocks[sec_num];
	  else if (sec_num < (124 + 128))
	  {
		  block_sector_t blocks[128];
		  cache_read(fs_device, inode->data.blocks[124], blocks, 0, BLOCK_SECTOR_SIZE);
		  return blocks[sec_num - 124];
	  }else if(sec_num < (124 + 128 + 128*128))
	  {
		  block_sector_t blocks[128];
		  cache_read(fs_device, inode->data.blocks[125], blocks, 0, BLOCK_SECTOR_SIZE);

		  block_sector_t lvl2 = blocks[(sec_num - 252) / 128];

		  cache_read(fs_device, lvl2, blocks, 0, BLOCK_SECTOR_SIZE);

		  return blocks[(sec_num - 252) % 128];
	  }
	  else return -1;
  }
  else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

static int inode_extend(struct inode* inode, off_t bytes_to_add)
{
	off_t offset = BLOCK_SECTOR_SIZE -  (inode->data.length % BLOCK_SECTOR_SIZE);
	block_sector_t new_sec_num = bytes_to_sectors(bytes_to_add - offset);
	block_sector_t cur_sec_num = bytes_to_sectors(inode->data.length);

	static char zeros[BLOCK_SECTOR_SIZE];

	/* additional block */
	block_sector_t count = 0;
	block_sector_t need_to_write = new_sec_num;
	/* fill direct links */
	if (cur_sec_num < 125)
	{
		need_to_write -= (124 - cur_sec_num);
		need_to_write = need_to_wrrite > 0 ? need_to_write : 0;
	}

	/* fill indirect links */
	if (need_to_write != 0 && cur_sec_num < (125 + 128))
	{
		block_sector_t start = cur_sec_num > 124 ? (cur_sec_num - 124) : 0;
		if (!start) count++;

		need_to_write -= 128 - start;
	}

	/* fil doubly-indirect links */
	if (need_to_write != 0)
	{
		block_sector_t start_total = cur_sec_num > 124 + 128 ? (cur_sec_num - 124 - 128) : 0;
		block_sector_t start_lvl1 = start_total / 128;
		block_sector_t start_lvl2 = start_total % 128;

		/* if level 1 block is not allocated */
		if (start_lvl1 == 0 && start_lvl2 == 0)
			count++;

		if(start_lvl2)
			need_to_write -= 128 - start_lvl2;	// lvl2 block is allocated already, so just fill it

		if(need_to_write > 0)
		{
			count += need_to_write / 128; 			// number of full lvl2 blocks needed to write
			count += need_to_write % 128 ? 1 : 0;	// one additional block may be needed
		}
	}

	/* allocate space for the list of new sectors */
	new_sec_num += count;
	block_sector_t* new_sectors = malloc((new_sec_num)* sizeof(block_sector_t));

	int added = 0;
	if(free_map_allocate_sparse(new_sec_num, new_sectors))
	{
		/* fill direct level */
		while (cur_sec_num < 124 && added < new_sec_num)
		{
			inode->data.sectors[cur_sec_num++] = new_sectors[added];
			cache_write(fs_device, new_sectors[added++], zeroes, 0, SECTOR_BLOCK_SIZE);
		}

		/* fill indirect level */
		if (added == new_sec_num) goto done;
		block_sector_t direct[128];
		if (added > 0)
		{
			inode->data.sectors[124] = new_sectors[added++];
			memset(direct, -1, 128*sizeof(block_sector_t));
		} else
		{
			cache_read(fs_device, inode->data.sectors[124], direct, 0, BLOCK_SECTOR_SIZE);
		}

		while(cur_sec_num < 124 + 128)
		{
			direct[cur_sec_num++ - 124] = new_sectors[added];
			cache_write(fs_device, new_sectors[added++], zeroes, 0, SECTOR_BLOCK_SIZE);
		}

		cache_write(fs_device,inode->data.sectors[124], direct, 0, SECTOR_BLOCK_SIZE);
		/* fill doubly indirect level */
		if (added == new_sec_num) goto done;

		block_sector_t indirect[128];
		/* check if block is new */
		if (added > 0)
		{
			inode->data.sectors[125] = new_sectors[added++];
			memset(indirect, -1, SECTOR_BLOCK_SIZE);
		} else
		{
			/* block was written previously */
			cache_read(fs_device, inode->data.sectors[125], indirect, 0, BLOCK_SECTOR_SIZE);
		}

		block_sector_t start_total = (cur_sec_num - 124 - 128);
		block_sector_t start_lvl1 = start_total / 128;
		block_sector_t start_lvl2 = start_total % 128;
		/* if direct inode was created before */
		if(start_lvl2)
		{
			/* read and fill it */
			cache_read(fs_device, indirect[start_lvl1], direct, 0, BLOCK_SECTOR_SIZE);
			while(added < new_sec_num && start_lvl2 < 128)
			{
				direct[start_lvl2++] = new_sectors[added];
				cache_write(fs_device, new_sectors[added++], zeroes, 0, SECTOR_BLOCK_SIZE);
			}
			cache_write(fs_device, indirect[start_lvl1], direct, 0, BLOCK_SECTOR_SIZE);
			/* advance */
			start_lvl1++;
			start_lvl2 = 0;
		}
		/* fill new nodes */
		while(added < new_sec_num)
		{
			memset(direct, 0, SECTOR_BLOCK_SIZE);
			indirect[start_lvl1] = new_sectors[added++];
			while(added < new_sec_num && start_lvl2 < 128)
			{
				direct[start_lvl2++] = new_sectors[added];
				cache_write(fs_device, new_sectors[added++], zeroes, 0, SECTOR_BLOCK_SIZE);
			}
			cache_write(fs_device, indirect[start_lvl1], direct, 0, BLOCK_SECTOR_SIZE);
			start_lvl1++;
			start_lvl2 = 0;
		}
		/* store indirect node to disk */
		cache_read(fs_device, inode->data.sectors[125], indirect, 0, BLOCK_SECTOR_SIZE);
	}
	else
	{
		/* failed to allocate space */
		free(new_sectors);
		return 0;
	}

	/* success */
	done:
	free(new_sectors);
	return 1;
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      memset(disk_inode->blocks, -1, 126*sizeof(block_sector_t));
      success = inode_extend(disk_inode, length);
      if (success)
    	  cache_write(fs_device, sector, disk_inode, 0, BLOCK_SECTOR_SIZE);
      free (disk_inode);
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  cache_read (fs_device, inode->sector, &inode->data, 0, BLOCK_SECTOR_SIZE);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

static void inode_free(struct inode_disk * inode)
{
	int i = 0;
	/* free direct blocks */
	for(; i < NDIRECT && inode>blocks[i] != -1; ++i)
	{
		free_map_release (inode>blocks[i], 1);
	}
	/* check if there are indirect blocks */
	if (i != NDIRECT || inode>blocks[NDIRECT] == -1) return;

	block_sector_t direct[128];
	/* read indirect blocks and free them */
	cache_read(fs_device, inode>blocks[NDIRECT], direct, 0, BLOCK_SECTOR_SIZE);
	for(i = 0; i < NINDIRECT && direct[i] != -1; ++i)
	{
		free_map_release (direct[i], 1);
	}
	free_map_release (inode>blocks[NDIRECT], 1);
	/* check if there are doubly-indirect blocks */
	if(i != NINDIRECT || inode>blocks[NDIRECT + 1] == -1) return;

	block_sector_t indirect[128];
	cache_read(fs_device, inode>blocks[NDIRECT + 1], indirect, 0, BLOCK_SECTOR_SIZE);
	int j = 0;
	/* free the rest */
	for(i = 0; i < NINDIRECT && indirect[i] != -1; ++i)
	{
		cache_read(fs_device, indirect[i], direct, 0, BLOCK_SECTOR_SIZE);
		for(j = 0; j < NINDIRECT && direct[j] != -1; ++j)
		{
			free_map_release (direct[j], 1);
		}
		free_map_release (indirect[i], 1);
	}
	free_map_release (inode>blocks[NDIRECT + 1], 1);
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          inode_free(&inode->data);
        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      cache_read (fs_device, sector_idx, buffer + bytes_read, sector_ofs, chunk_size);
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;

  if (inode->deny_write_cnt)
    return 0;

  if(size + offset > inode->data.length)
  {
	  int success = inode_extend(inode, size + offset - inode->data.length);
	  if (success == 0) return 0;
  }

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      cache_write (fs_device, sector_idx, buffer + bytes_written, sector_ofs, chunk_size);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}
