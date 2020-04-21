void insert_in_free_list(sf_block* block);


void insert_at_index_in_free_list(sf_block* block, int i);


sf_block *delete_first_node_from_free_list(int i);


void remove_block_from_free_list(sf_block *block);


int check_size_in_list(size_t block_size);


size_t get_nearest_16_multiple(size_t size);


sf_block *search_in_free_list(size_t size);


int is_list_empty(int i);


sf_block *split_the_block(sf_block *block, size_t required_size);


sf_block *coalesce_block(sf_block *block);


void is_ptr_valid(void *ptr);

int is_realloc_ptr_valid(void *ptr);

sf_block *grow_heap(size_t);