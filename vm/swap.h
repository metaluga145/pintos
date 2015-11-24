#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "vm/page.h"

void swap_init(void);

void swap_out(struct page*);
void swap_in(struct page*);
void swap_free(struct page*);

int swap_check_page(struct page*);
#endif
