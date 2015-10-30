#ifndef VM_SWAP_H
#define VM_SWAP_H

void swap_init(void);

void swap_out(struct page*);
void swap_in(struct page*);

#endif
