#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"

#include "vm/page.h"
#include "vm/frame.h"

/*
 * structure to pass arguments to a child's thread and set up them.
 */
static struct args_tmp
{
	size_t argc;					// argc (to stack)
	char** argv;					// array of char*
	size_t total_length;			// total length of args. used to speed up storing on the stack.
	struct semaphore loading_block;	// sema used to wait while child is loaded.
	bool loaded;					// if loading was successful.
	struct process* cur_proc;		// pointer to the child's process structure. Need to be stored to thread structure.
	struct file* executable;		// to return the pointer to the executable file.
};

static struct list threads_children;
static struct lock list_lock;

static thread_func start_process NO_RETURN;
static bool load (struct args_tmp* args, void (**eip) (void), void **esp);

#define MAX_ARGS 128
#define MAX_LINE_SIZE 4000

/* initialize the list and the lock */
void process_init(void)
{
	list_init(&threads_children);
	lock_init(&list_lock);
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *cmdline)
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;

  /* setting up arguments */
  if (PGSIZE - 1 == strlcpy (fn_copy, cmdline, PGSIZE) && cmdline[PGSIZE - 1] != '\0')
  {
	  /* if cmd is too big to feet in one page, dealloca memory and return -1 */
	  palloc_free_page (fn_copy);
	  return TID_ERROR;
  }
//---------------------------------------------------------------------------
  /* create and initialize temporal structure for arguments */
  struct args_tmp* args = malloc(sizeof(struct args_tmp));
	if(args == NULL)
	{
		free(fn_copy);
		return TID_ERROR;
	}
  args->argc = 0;
  args->argv = malloc(MAX_ARGS*sizeof(char*));
	if(args->argv == NULL)
	{
		free(fn_copy);
		free(args);
		return TID_ERROR;
	}
  sema_init(&args->loading_block, 0);
  args->loaded = false;
  args->total_length = 0;
//-------------------------------------------------------------------------------
  /* parse command line */
  char* token, *save_ptr;
  for (token = strtok_r (fn_copy, " ", &save_ptr);
		  token != NULL && args->argc < MAX_ARGS;
		  token = strtok_r (NULL, " ", &save_ptr))
  {
	  args->argv[args->argc] = token;
	  args->argc++;
	  /* calculate the length of an argument (including '\0'). */
	  args->total_length += (*save_ptr != '\0' || *(save_ptr - 1) == '\0') ? (save_ptr - token) : (save_ptr - token + 1);
  }

//--------------------------------------------------------------------------------
  /* allocate and init child's process structure */
  struct process* child = malloc(sizeof(struct process));
	if(child == NULL)
	{
		free(args->argv);
		free(args);
		free(fn_copy);
		return TID_ERROR;
	}	
  list_init(&child->children);
  list_init(&child->fds);
  child->my_lock = malloc(sizeof(struct parent_list_guard));
	if(child->my_lock == NULL)
	{
		free(child);
		free(args->argv);
		free(args);
		free(fn_copy);
		return TID_ERROR;
	}
  lock_init(&child->my_lock->list_lock);
  child->my_lock->count = 1;
  child->my_lock->parent_alive = true;
  child->exited = false;
  sema_init(&child->wait, 0);

  args->cur_proc = child;	// child's thread should have pointer to its process instance

  struct thread* parent = thread_current();

  /* check if parent is a process or a thread, and store appropriate pointers to the lock and to the list */
  struct lock* parents_lock;
  struct list* parents_list;
  if (parent->proc)
  {
	  child->parent_lock = parent->proc->my_lock;
	  parents_lock = &parent->proc->my_lock->list_lock;	// avoid trying to modify exit status before stored on the list of children
	  parents_list = &parent->proc->children;
  }
  else
  {
	  child->parent_lock = NULL;
	  parents_lock = &list_lock;
	  parents_list = &threads_children;
  }
  /*
   * avoid race conditions when child tries to modify itself,
   * while is not stored on the list of children
   */
  lock_acquire(parents_lock);
//--------------------------------------------------------------------------------
  /* check if everything can fit in one page */
  args->total_length += 8 - (args->total_length % 4); 	// account for alignment and NULL
  // calculate total length accounting for argv ptr, argc and return addr on the stack
  size_t full_length = args->total_length + sizeof(char*)*(args->argc + 2) + sizeof(int);
  if(full_length > PGSIZE)
	  goto free_all;
//---------------------------------------------------------------------------------
  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (args->argv[0], PRI_DEFAULT, start_process, args);
//---------------------------------------------------------------------------------
  /* waiting while loading is finished */
  sema_down(&args->loading_block);
  // remember executable file
  child->executable = args->executable;
  // if failed tid = -1
  free_all: if(!args->loaded)
	  tid = TID_ERROR;

  /* deallocate memory */
  palloc_free_page (fn_copy);
  free(args->argv);
  free(args);

  if (tid != TID_ERROR)
  {
	  /* if everything is OK, store pid, and add child to list of children */
	  child->pid = tid;
	  list_push_back(parents_list, &child->elem);
	if(parent->proc) parent->proc->my_lock->count++;
  }
  else
  {
	  /* if fail, make child to deallocate its resources himself (thread_exit() and process_exit() will be called) */
	  child->exited = true;	// make child to deallocate resources himself
  }
  lock_release(parents_lock);
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *args_)
{
	struct args_tmp *args = args_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (args, &if_.eip, &if_.esp);

  /* return result of loading to parent and unlock him */
  args->loaded = success;
  thread_current()->proc = args->cur_proc;
  sema_up(&args->loading_block);

  if (!success) 
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid)
{
	/* acquire the lock for the list */
	/* need to choose correct lock and list, because the init thread is not a process */
	struct process* cur_proc = thread_current()->proc;
	struct lock* parents_lock;
	struct list* parents_list;
	if (cur_proc)
	{
		parents_lock = &cur_proc->my_lock->list_lock;
		parents_list = &cur_proc->children;
	}
	else
	{
		parents_lock = &list_lock;
		parents_list = &threads_children;
	}

	struct process* child;
	lock_acquire(parents_lock);
	/* find child */
	struct list_elem* e;
	for(e = list_begin(parents_list);
			e != list_end(parents_list);)
	{
		child = list_entry(e, struct process, elem);
		if(child->pid == child_tid)
			break;
	}
	/* if child_tid is not a child if this process */
	if (e == list_end(parents_list))
	{
		lock_release(parents_lock);
		return -1;
	}
	lock_release(parents_lock);

	/* wait child to exit */
	sema_down(&child->wait);

	/* when child exited, get his exit code, remove from the list and free memory */
	lock_acquire(parents_lock);
	int ret = child->exit_status;
	list_remove(&child->elem);
	lock_release(parents_lock);
	free(child);

	// pass exit status
	return ret;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  struct process* cur_proc = cur->proc;
  if(cur_proc)
  {
	  // IF THIS IS PROCESS
	  /* ----  CHILDREN SECTION ---- */
	  /* notify children that parent dies */
	  lock_acquire(&cur_proc->my_lock->list_lock);
	  (cur_proc->my_lock->count)--;
	  cur_proc->my_lock->parent_alive = false;

	  struct list_elem* e;
	  /* dealloc zombies */
	  for(e = list_begin(&cur_proc->children);
			  e != list_end(&cur_proc->children);)
	  {
		  struct process* child = list_entry(e, struct process, elem);
		  if(child->exited)
		  {
			  e = list_remove(e);
			  free(child);
		  }
		  else
			  e = list_next(e);
	  }
	  /* if no children left in the group, free the lock */
	  bool lock_is_needed = cur_proc->my_lock->count;
	  lock_release(&cur_proc->my_lock->list_lock);
	  if (!lock_is_needed)
		  free(cur_proc->my_lock);
	  /* ---- END OF CHILDREN SECTION ---- */

	  /* ---- PARENT SECTION ---- */
	  /* next we will modify critical section in the list, lock should be acquired */
	if (cur_proc->parent_lock)
	{
	  lock_acquire(&cur_proc->parent_lock->list_lock);
	  file_close(cur_proc->executable);		// close executable file
	  cur_proc->parent_lock->count--;		// decrement number of participants in the group
	  struct parent_list_guard* lock = cur_proc->parent_lock; /* to free lock if necessary */
	  lock_is_needed = cur_proc->parent_lock->count;		// check if it needs to be deallocated
	  if(cur_proc->parent_lock->parent_alive && !(cur_proc->exited))
	  {
		  /* if parent is alive, change status and release resources */
		  cur_proc->exited = true;
		  sema_up(&cur_proc->wait);
	  }
	  /* if parent is dead, free memory */
	  else  free(cur_proc);

	  lock_release(&lock->list_lock);
	  if(!lock_is_needed) free(lock);
	}
	else
	{
		/* if process was spawned by initial thread */
		lock_acquire(&list_lock);
		file_close(cur_proc->executable);
		cur_proc->exited = true;
		sema_up(&cur_proc->wait);
		lock_release(&list_lock);
	}
  }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, struct args_tmp* args);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (struct args_tmp* args, void (**eip) (void), void **esp)
{
	const char *file_name = args->argv[0];
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, args))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
	 if(success)
	 {
		 args->executable = file;			// if success, keep executable file open
		 file_deny_write(args->executable);	// deny writings in it
	 }
	 else file_close (file);				// otherwise close

  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      //uint8_t *kpage = palloc_get_page (PAL_USER);
      struct page* pg = page_construct(upage, writable & PG_FILE);
      if(!pg) return false;		/* malloc failed to allocate kernel space */

      uint8_t* kpage = frame_alloc(pg, PAL_USER);

      pg->file = file;
      pg->ofs = ofs;
      pg->read_bytes = read_bytes;

      /*check for memory leaks in destructing pg */
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          frame_free (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
    	  frame_free (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, struct args_tmp* args)
{
  uint8_t *kpage;
  bool success = false;
  /* obtain and install a new page */
	  success = page_push_stack(PHYS_BASE-PGSIZE);
      if (success)
      {
    	  /* if new page is installed successfully, put args on the stack */
    	  char* esp_ = (char*)PHYS_BASE;
    	  /* since we know total length, we can calculate where to put pointers to arguments */
    	  char** esp_argv = (char**)(esp_ - (char*)(args->total_length));
    	  int i;
    	  for(i = args->argc - 1; i >= 0 ; --i)
    	  {
    		  int len = strlen(args->argv[i])+1;
    		  esp_ -= len;
    		  memcpy(esp_, args->argv[i], len);
    		  --esp_argv;
    		  *esp_argv = esp_;
    	  }
    	  /* put pointer to argv on the stack */
    	  esp_ = (char*)esp_argv;
    	  --esp_argv;
    	  *esp_argv = esp_;
    	  /* put argc */
    	  esp_argv -= sizeof(int)/sizeof(char**);
    	  memcpy(esp_argv, &(args->argc), sizeof(int));
    	  /* return address */
    	  --esp_argv;
    	  /* final value of esp */
    	  *esp = esp_argv;
      }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
