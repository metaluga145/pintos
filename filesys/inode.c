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

static void inode_free(struct inode_disk*, int);

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

static int inode_extend(struct inode_disk* inode, off_t bytes_to_add)
{
	off_t offset = BLOCK_SECTOR_SIZE -  (inode->length % BLOCK_SECTOR_SIZE);
	block_sector_t new_sec_num = bytes_to_sectors(bytes_to_add - offset);
	block_sector_t cur_sec_num = bytes_to_sectors(inode->length);

	static char zeroes[BLOCK_SECTOR_SIZE];

	int start = (int)cur_sec_num;
	block_sector_t count = 0;
	block_sector_t new_sector = 0;
	int i = 0;
	if (start < NDIRECT)
	{
		i = start;
		/* free direct blocks */
		while(i < NDIRECT && count < new_sec_num)
		{
			if (!free_map_allocate(1, &new_sector))
			{
				inode_free(inode, start + 1);
				return 0;
			}
			cache_write(fs_device, new_sector, zeroes, 0, BLOCK_SECTOR_SIZE);
			inode->blocks[i] = new_sector;
			++i;
			++count;
		}

		/* check if there are indirect blocks */
		if (count == new_sec_num) return 1;
	}

	block_sector_t direct[NINDIRECT];
	/* read indirect blocks and free them */
	if (start < NINDIRECT)
	{
		if(i == 0) i = start - NDIRECT;
		else i = 0;

		if (inode->blocks[NDIRECT] != -1)
		{
			cache_read(fs_device, inode->blocks[NDIRECT], direct, 0, BLOCK_SECTOR_SIZE);
		}
		else
		{
			ASSERT(i == 0);
			if (!free_map_allocate(1, &new_sector))
			{
				inode_free(inode, start + 1);
				return 0;
			}
			inode->blocks[NDIRECT] = new_sector;
			memset(direct, -1, NINDIRECT * sizeof(block_sector_t));
		}

		while(i < NINDIRECT && count < new_sec_num)
		{
			if (!free_map_allocate(1, &new_sector))
			{
				cache_write(fs_device, inode->blocks[NDIRECT], direct, 0, BLOCK_SECTOR_SIZE);
				inode_free(inode, start + 1);
				return 0;
			}
			cache_write(fs_device, new_sector, zeroes, 0, BLOCK_SECTOR_SIZE);
			direct[i] = new_sector;
			++i;
			++count;
		}

		/* check if there are indirect blocks */
		if (count == new_sec_num) return 1;
	}

	int j = 0;
	if (i == 0)
	{
		int num = start - NDIRECT - NINDIRECT;
		i = num / NINDIRECT;
		j = num % NINDIRECT;
	}
	else i = 0;
	block_sector_t indirect[128];
	if (inode->blocks[NDIRECT + 1] != -1)
	{
		cache_read(fs_device, inode->blocks[NDIRECT + 1], indirect, 0, BLOCK_SECTOR_SIZE);
		if(indirect[i] != -1)
		{
			cache_read(fs_device, indirect[i], direct, 0, BLOCK_SECTOR_SIZE);
			while(j < NINDIRECT && count < new_sec_num)
			{
				if (!free_map_allocate(1, &new_sector))
				{
					cache_write(fs_device, indirect[i], direct, 0, BLOCK_SECTOR_SIZE);
					inode_free(inode, start + 1);
					return 0;
				}
				cache_write(fs_device, new_sector, zeroes, 0, BLOCK_SECTOR_SIZE);
				direct[i] = new_sector;
				++j;
				++count;
			}
			if (count == new_sec_num) return 1;

			++i;
		}
	}
	else
	{
		ASSERT(i == 0);
		if (!free_map_allocate(1, &new_sector))
		{
			inode_free(inode, start + 1);
			return 0;
		}
		inode->blocks[NDIRECT + 1] = new_sector;
		memset(direct, -1, NINDIRECT * sizeof(block_sector_t));
	}

	/* free the rest */
	while(i < NINDIRECT && count < new_sec_num)
	{
		if (!free_map_allocate(1, &new_sector))
		{
			cache_write(fs_device, inode->blocks[NDIRECT + 1], indirect, 0, BLOCK_SECTOR_SIZE);
			inode_free(inode, start + 1);
			return 0;
		}
		direct[i] = new_sector;
		memset(direct, -1, NINDIRECT * sizeof(block_sector_t));
		while(j < NINDIRECT && count < new_sec_num)
		{
			if (!free_map_allocate(1, &new_sector))
			{
				cache_write(fs_device, indirect[i], direct, 0, BLOCK_SECTOR_SIZE);
				cache_write(fs_device, inode->blocks[NDIRECT + 1], indirect, 0, BLOCK_SECTOR_SIZE);
				inode_free(inode, start + 1);
				return 0;
			}
			cache_write(fs_device, new_sector, zeroes, 0, BLOCK_SECTOR_SIZE);
			direct[i] = new_sector;
			++j;
			++count;
		}
		cache_write(fs_device, indirect[i], direct, 0, BLOCK_SECTOR_SIZE);

		if (count == new_sec_num)
		{
			cache_write(fs_device, inode->blocks[NDIRECT + 1], indirect, 0, BLOCK_SECTOR_SIZE);
			return 1;
		}

		++i;
		++count;
	}

	cache_write(fs_device, inode->blocks[NDIRECT + 1], indirect, 0, BLOCK_SECTOR_SIZE);
	if (count == new_sec_num) return 1;

	inode_free(inode, start + 1);
	return 0;

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

static void inode_free(struct inode_disk * inode, int start)
{
	int i = 0;
	if (start < NDIRECT)
	{
		i = start;
		/* free direct blocks */
		for(; i < NDIRECT && inode->blocks[i] != -1; ++i)
		{
			free_map_release (inode->blocks[i], 1);
		}

		/* check if there are indirect blocks */
		if (i != NDIRECT || inode->blocks[NDIRECT] == -1) return;
	}

	block_sector_t direct[128];
	/* read indirect blocks and free them */
	if (start < NINDIRECT)
	{
		if(i == 0) i = start - NDIRECT;
		else i = 0;

		cache_read(fs_device, inode->blocks[NDIRECT], direct, 0, BLOCK_SECTOR_SIZE);
		for(; i < NINDIRECT && direct[i] != -1; ++i)
		{
			free_map_release (direct[i], 1);
		}
		free_map_release (inode->blocks[NDIRECT], 1);
		/* check if there are doubly-indirect blocks */
		if(i != NINDIRECT || inode->blocks[NDIRECT + 1] == -1) return;
	}

	int j = 0;
	if (i == 0)
	{
		int num = start - NDIRECT - NINDIRECT;
		i = num / NINDIRECT;
		j = num % NINDIRECT;
	}
	else i = 0;
	block_sector_t indirect[128];
	cache_read(fs_device, inode->blocks[NDIRECT + 1], indirect, 0, BLOCK_SECTOR_SIZE);

	/* free the rest */
	for(; i < NINDIRECT && indirect[i] != -1; ++i)
	{
		cache_read(fs_device, indirect[i], direct, 0, BLOCK_SECTOR_SIZE);
		for(; j < NINDIRECT && direct[j] != -1; ++j)
		{
			free_map_release (direct[j], 1);
		}
		free_map_release (indirect[i], 1);
		j = 0;
	}
	free_map_release (inode->blocks[NDIRECT + 1], 1);
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
          inode_free(&inode->data, 0);
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
	  int success = inode_extend(&inode->data, size + offset - inode->data.length);
	  if (success == 0) return 0;
	  cache_write (fs_device, inode->sector, &inode->data, 0, BLOCK_SECTOR_SIZE);
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
