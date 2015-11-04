/* Encrypts, then decrypts, 2 MB of memory and verifies that the
   values are as they should be. */

#include <string.h>
#include "tests/arc4.h"
#include "tests/lib.h"
#include "tests/main.h"
#include <stdio.h>

#define SIZE (2 * 1024 * 1024)
#define PGS 1<<12

static char buf[SIZE];

void
test_main (void)
{
//printf("hi1\n");
  struct arc4 arc4;
//printf("hi2\n");
  size_t i;

  /* Initialize to 0x5a. */
  msg ("initialize");
//printf("buf = %p\n", buf);
/*
for(i = 0; i < SIZE; i+= PGS)
{
char * addr = ((char *)((unsigned)buf + i));
  memset (addr, 0x5a, PGS);
printf("addr = %p, but[] = %u\n", addr, *addr);
}
*/
  memset (buf, 0x5a, sizeof buf);
  /* Check that it's all 0x5a. */
  msg ("read pass");
  for (i = 0; i < SIZE; i++)
    if (buf[i] != 0x5a)
{
printf("%p\n", buf+i);
printf("char = %u\n", *(buf+i));
printf("char = %u\n", *(buf+i+1));
      fail ("byte %zu != 0x5a", i);
}

  /* Encrypt zeros. */
  msg ("read/modify/write pass one");
  arc4_init (&arc4, "foobar", 6);
  arc4_crypt (&arc4, buf, SIZE);

  /* Decrypt back to zeros. */
  msg ("read/modify/write pass two");
  arc4_init (&arc4, "foobar", 6);
  arc4_crypt (&arc4, buf, SIZE);

  /* Check that it's all 0x5a. */
  msg ("read pass");
  for (i = 0; i < SIZE; i++)
    if (buf[i] != 0x5a)
      fail ("byte %zu != 0x5a, %p", i, (buf+i));
//printf("finished\n");
}
