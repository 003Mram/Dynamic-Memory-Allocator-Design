/**
 * All functions you make for the assignment must be implemented in this file.
 * Do not submit your assignment with a main function in this file.
 * If you submit with a main function in this file, you will get a zero.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "debug.h"
#include "sfmm.h"
#include "helper.h"

void *sf_malloc(size_t size) {
    sf_prologue *ptr_heap_start = NULL;
    sf_epilogue *ptr_heap_end = NULL;
    size_t block_size = 0;
    sf_block *block = NULL;
    if(size == 0){
        return NULL;
    }

    /*check for if heap is initially empty and call sf_mem_grow()
    * Setup the prologue and epilogue blocks
    */
    if(sf_mem_start() == sf_mem_end()){

        //Initialization of the heap and free lists
        ptr_heap_start = (sf_prologue *) sf_mem_grow();
        ptr_heap_start->header = 32 | 3;
        ptr_heap_start->footer =  ptr_heap_start->header ^ sf_magic();
        ptr_heap_end = (sf_epilogue *) (sf_mem_end());
        ptr_heap_end--;
        ptr_heap_end->header = 2;

        //
        sf_header* header = (sf_header *)(ptr_heap_start+1);
        sf_footer* footer = (sf_footer *)(ptr_heap_end-1);
        block_size = (footer+1-header)*sizeof(sf_header);
        *header = block_size | 1;
        *footer = *header ^ sf_magic();

        //Free lists initialization. Pointing sentinal node's prev and next to itself
        for(int i=0;i<(NUM_FREE_LISTS);i++){
            sf_free_list_heads[i].body.links.next = &sf_free_list_heads[i];
            sf_free_list_heads[i].body.links.prev = &sf_free_list_heads[i];
        }

         block = (sf_block *)(header-1);

        insert_in_free_list(block);
    }

    block_size = size + sizeof(sf_header) + sizeof(sf_footer);
    block_size = get_nearest_16_multiple(block_size);
    block = search_in_free_list(block_size);
    // sf_show_free_lists();
    if(block != NULL){
        block = split_the_block(block,block_size);
        return (void *)((void *)(block) + sizeof(sf_footer) + sizeof(sf_header));
    }else{
        block = grow_heap(block_size);
        if(block == NULL){
            return NULL;
        }
        block = split_the_block(block, block_size);
        return (void *)((void *)(block) + sizeof(sf_footer) + sizeof(sf_header));
    }

    return NULL;
}

void sf_free(void *pp) {
    is_ptr_valid(pp);

    sf_block *free_block = (sf_block *)((void *)(pp)-sizeof(sf_header)-sizeof(sf_footer));

    free_block->header = (free_block->header & (BLOCK_SIZE_MASK | PREV_BLOCK_ALLOCATED));

    //Changing the prev_footer and header of the next block after freeing a block=
    sf_block *next_block = (sf_block *)((void *)free_block + (free_block->header&BLOCK_SIZE_MASK));
    next_block->prev_footer = free_block->header ^ sf_magic();
    next_block->header = next_block->header & (BLOCK_SIZE_MASK | THIS_BLOCK_ALLOCATED);
    next_block = (sf_block *)((void *)free_block + (free_block->header&BLOCK_SIZE_MASK));

    sf_footer *footer = (sf_footer *)((void *)next_block + (next_block->header&BLOCK_SIZE_MASK));
    *footer = next_block->header ^ sf_magic();

    free_block = coalesce_block(free_block);
    insert_in_free_list(free_block);
    // sf_show_blocks();
    return;
}

void *sf_realloc(void *pp, size_t rsize) {
    if(is_realloc_ptr_valid(pp)){
        sf_errno = EINVAL;
        return NULL;
    }

    if(rsize == 0){
        sf_free(pp);
        return NULL;
    }

    sf_block *block = (sf_block *)(pp-sizeof(sf_header)-sizeof(sf_footer));
    void *new_pp = NULL;
    size_t size = (block->header & BLOCK_SIZE_MASK) - sizeof(sf_header) - sizeof(sf_footer);
    size_t aligned_rsize = get_nearest_16_multiple(rsize + sizeof(sf_header) + sizeof(sf_footer));

    if(rsize > size){
        new_pp = sf_malloc(rsize);
        if(new_pp == NULL){
            return NULL;
        }
        memcpy(new_pp,pp,size);
        sf_free(pp);
        return new_pp;
    }else{
        block = split_the_block(block,aligned_rsize);
        return pp;
    }
    return NULL;
}


/*Given a pointer to a block inserts it in the appropriate free list
* @param Pointer to the free sf_block
*
*/
void insert_in_free_list(sf_block* block){
    int M = 32;
    int low = M/2;
    int high = M;
    size_t size = block->header & BLOCK_SIZE_MASK;
    if(size == M){
        insert_at_index_in_free_list(block,0);
        return;
    }
    for(int i=1;i<(NUM_FREE_LISTS-1);i++){
        low = low*2;
        high = high*2;

        if(size>low && size<=high){
            // printf("Index of insertion:%d\n", i);
            insert_at_index_in_free_list(block,i);
            return;
        }
    }

    insert_at_index_in_free_list(block, NUM_FREE_LISTS-1);
}


/*Given a pointer to a free sf_block block and index i at which it needs
* to be inserted, the function inserts the block right after the
* sentinal node at index i.
*
* @param block pointer of the block to be inserted
* @param i Index in the free list at which it needs to be inserted
* @return
*/
void insert_at_index_in_free_list(sf_block* block, int i){
    sf_block* sentinal = &sf_free_list_heads[i];
    sf_block* temp = sentinal->body.links.next;

    sentinal->body.links.next = block;
    // printf("Changed next of sentinal node:%p\n", sentinal->body.links.next);
    block->body.links.next = temp;
    block->body.links.prev = sentinal;
    temp->body.links.prev = block;
    // printf("Changed next of sentinal node:%p\n", sentinal->body.links.next);
    return;
}

int check_size_in_list(size_t size){
    int M = 32;
    int low = M/2;
    int high = M;
    if(size == 32){
        return 0;
    }

    for(int i=1;i<(NUM_FREE_LISTS-1);i++){
        low = low*2;
        high = high*2;

        if(size>low && size<=high){
            return i;
        }
    }

    if(size > high){
        return NUM_FREE_LISTS-1;
    }

    return -1;
}


/*This method gets the nearest multiple of 16 for a given size to
* meet alignment requirements
*/
size_t get_nearest_16_multiple(size_t size){
    size_t new_size= (size/16) * 16;
    if(size%16 != 0){
        new_size += 16;
    }

    return new_size;

}


/*Search in the free lists array of doubly circular linked lists
* to get a free block of atleast given input size
* @param size The number of bytes required with alignment requirements
* and header/footer data
* @return Pointer to the sf_block that has atleast input size.
* If no free list has size satisfying our request returns NULL
*/
sf_block *search_in_free_list(size_t size){
    int index = check_size_in_list(size);

    /*Search till last but one index as last list do not have proper bounds.
    * So, we search the last list differently if we don't return in this loop.
    */
    while(index < NUM_FREE_LISTS){
        // if(!is_list_empty(index)){
        //     return delete_first_node_from_free_list(index);
        // }

        sf_block *last_list = &sf_free_list_heads[index];
        sf_block *itr = last_list->body.links.next;
        while(itr != last_list){
            if((itr->header & BLOCK_SIZE_MASK) >= size){
                remove_block_from_free_list(itr);
                return itr;
            }

            itr = itr->body.links.next;
        }

        index++;
    }

    // sf_block *last_list = &sf_free_list_heads[NUM_FREE_LISTS-1];
    // sf_block *itr = last_list;
    // while(itr->body.links.next != last_list){
    //     if((itr->header & BLOCK_SIZE_MASK) >= size){
    //         remove_block_from_free_list(itr);
    //         return itr;
    //     }
    //     itr = itr->body.links.next;
    // }

    return NULL;
}


/*Checks if the free list at given index is empty or not
* @param Index in the free list array
* @returns 0 if the list is not empty.
* -1 if the list is empty.
*/
int is_list_empty(int i){
    sf_block* sentinal = &sf_free_list_heads[i];
    sf_block* temp = sentinal;
    if(temp->body.links.next != sentinal){
        return 0;
    }

    return -1;
}

/*Removes and returns the first node from the free list at
* the given index. Assumes that the list is not empty
* @param i Index of the free list
* @return Pointer to the first sf_block in the list
*/
sf_block *delete_first_node_from_free_list(int i){
    sf_block* sentinal = &sf_free_list_heads[i];
    sf_block* block = sentinal->body.links.next;
    sf_block* temp = block->body.links.next;
    sentinal->body.links.next = temp;
    temp->body.links.prev = sentinal;
    return block;
}


void remove_block_from_free_list(sf_block *block){
    sf_block *next = block->body.links.next;
    sf_block *prev = block->body.links.prev;

    prev->body.links.next = next;
    next->body.links.prev = prev;
}


/*
*/
sf_block *split_the_block(sf_block *block, size_t required_size){
    size_t block_size = block->header & BLOCK_SIZE_MASK;
    sf_block *next_block = NULL;
    sf_footer *next_footer = NULL;

    //If the block_size
    if(block_size - required_size < 32){
        block->header = block->header | THIS_BLOCK_ALLOCATED;
        next_block = (sf_block *)((void *)(block) + block_size);
        next_footer = (sf_footer *)((void *)next_block + (next_block->header & BLOCK_SIZE_MASK));
        next_block->header = (next_block->header) | PREV_BLOCK_ALLOCATED;
        next_block->prev_footer = block->header ^ sf_magic();

        //Checking for epilogue if the free block is next to epilogue
        if((void *) next_block != (void *) next_footer){
            *next_footer = next_block->header ^ sf_magic();
        }
        return block;
    }

    block->header = required_size | (block->header & PREV_BLOCK_ALLOCATED);
    block->header = block->header | THIS_BLOCK_ALLOCATED;

    //Footer of the block left after splitting
    next_footer = (sf_footer *)((void *)block + block_size);

    //New Block formed after splitting the block for allocation
    next_block = (sf_block *)((void *)block + required_size);

    next_block->prev_footer = block->header ^ sf_magic();
    next_block->header = (block_size - required_size) | 1;
    *next_footer = next_block->header ^ sf_magic();
    next_block = coalesce_block(next_block);
    insert_in_free_list(next_block);

    return block;
}


/* Coalesces the freed block with any free blocks the just precedes or succeeds
* the current freed block till an allocated block is found
*/
sf_block *coalesce_block(sf_block *block){
    sf_block *new_block = block;
    size_t size = (block->header & BLOCK_SIZE_MASK);
    sf_block *next_block = (sf_block *)((void *)(block)+ size);
    int is_prev_allocated = block->header & PREV_BLOCK_ALLOCATED;
    int is_next_allocated = (next_block->header & THIS_BLOCK_ALLOCATED);

    while(is_prev_allocated == 0){
        new_block = (sf_block *)((void *)block - ((block->prev_footer ^ sf_magic()) & BLOCK_SIZE_MASK));
        size = size + ((block->prev_footer ^ sf_magic()) & BLOCK_SIZE_MASK);
        is_prev_allocated = (new_block->header  & PREV_BLOCK_ALLOCATED);
        remove_block_from_free_list(new_block);
    }

    new_block->header = size | 1;
    next_block->prev_footer = new_block->header ^ sf_magic();

    while(is_next_allocated == 0){
        size = size + (next_block->header & BLOCK_SIZE_MASK);
        remove_block_from_free_list(next_block);
        next_block = (sf_block *)((void *)next_block + (next_block->header & BLOCK_SIZE_MASK));
        is_next_allocated = (next_block->header & THIS_BLOCK_ALLOCATED);
    }

    new_block->header = size | 1;
    next_block->prev_footer = new_block->header ^ sf_magic();

    return new_block;
}

void is_ptr_valid(void *ptr){
    //Check if the ptr is null
    if(ptr == NULL){
        abort();
    }

    sf_block *free_block = (sf_block *)(ptr-sizeof(sf_header)-sizeof(sf_footer));
    sf_block *next_block = (sf_block *)((void *)free_block + (free_block->header & BLOCK_SIZE_MASK));
    sf_block *prev_block = (sf_block *)((void *)free_block - (((free_block->prev_footer) ^ sf_magic()) & BLOCK_SIZE_MASK));

    //Check if the header before the end of prologue
    if((ptr-sizeof(sf_header)) < (sf_mem_start()+sizeof(sf_prologue))){
        abort();
    }

    //Check if the footer address is after the beginning of epilogue
    if((ptr + ((free_block->header & BLOCK_SIZE_MASK) - sizeof(sf_header) - sizeof(sf_footer))) >= (sf_mem_end()-sizeof(sf_epilogue))){
        abort();
    }

    //Check if the allocated bit of the block is 1
    if((free_block->header & THIS_BLOCK_ALLOCATED) == 0){
        abort();
    }

    //Check if the block size is less than the minimum size(M=32)
    if((free_block->header & BLOCK_SIZE_MASK) < 32){
        abort();
    }

    //Check if prev_alloc field is 0, indicating that the previous block is free, but the alloc field of the previous block header is not 0
    if((free_block->header & PREV_BLOCK_ALLOCATED) == 0 && (prev_block->header & THIS_BLOCK_ALLOCATED) !=0){
        abort();
    }

    if((next_block->prev_footer ^ sf_magic()) != (free_block->header)){
        abort();
    }
}

int is_realloc_ptr_valid(void *ptr){
    //Check if the ptr is null
    if(ptr == NULL){
        return -1;
    }

    sf_block *free_block = (sf_block *)(ptr-sizeof(sf_header)-sizeof(sf_footer));
    sf_block *next_block = (sf_block *)((void *)free_block + (free_block->header & BLOCK_SIZE_MASK));
    sf_block *prev_block = (sf_block *)((void *)free_block - (((free_block->prev_footer) ^ sf_magic()) & BLOCK_SIZE_MASK));

    //Check if the header before the end of prologue
    if((ptr-sizeof(sf_header)) < (sf_mem_start()+sizeof(sf_prologue))){
        return -1;
    }

    //Check if the footer address is after the beginning of epilogue
    if((ptr + ((free_block->header & BLOCK_SIZE_MASK) - sizeof(sf_header) - sizeof(sf_footer))) >= (sf_mem_end()-sizeof(sf_epilogue))){
        return -1;
    }

    //Check if the allocated bit of the block is 1
    if((free_block->header & THIS_BLOCK_ALLOCATED) == 0){
        return -1;
    }

    //Check if the block size is less than the minimum size(M=32)
    if((free_block->header & BLOCK_SIZE_MASK) < 32){
        return -1;
    }

    //Check if prev_alloc field is 0, indicating that the previous block is free, but the alloc field of the previous block header is not 0
    if((free_block->header & PREV_BLOCK_ALLOCATED) == 0 && (prev_block->header & THIS_BLOCK_ALLOCATED) !=0){
        return -1;
    }

    if((next_block->prev_footer ^ sf_magic()) != (free_block->header)){
        return -1;
    }

    return 0;
}

sf_block *grow_heap(size_t size){
    void *ptr = NULL;
    size_t avaliable_size = 0;
    sf_block *new_block = NULL;
    sf_epilogue *new_epilogue = NULL;
    sf_footer* footer = NULL;

    while(size > avaliable_size){
        ptr = sf_mem_grow();
        if(ptr==NULL){
            sf_errno = ENOMEM;
            insert_in_free_list(new_block);
            return NULL;
        }
        new_block = (sf_block *)(ptr - sizeof(sf_epilogue) - sizeof(footer));
        new_epilogue = (sf_epilogue *)(sf_mem_end());
        new_epilogue--;
        new_epilogue->header = 2;
        new_block->header = PAGE_SZ | (((new_block->prev_footer ^ sf_magic()) & THIS_BLOCK_ALLOCATED) >> 1);
        footer = (sf_footer *)(new_epilogue-1);
        *footer = (new_block->header ^ sf_magic());
        new_block = coalesce_block(new_block);
        avaliable_size = new_block->header & BLOCK_SIZE_MASK;
    }

    return new_block;
}

