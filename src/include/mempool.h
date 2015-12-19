#ifndef __MEMPOOL_H__
#define __MEMPOOL_H__

struct mem_chunk
{
    uchar *chunk_addr;
    TAILQ_ENTRY(mem_chunk) mem_chunk_link;
};
typedef struct mem_chunk * mem_chunk_t;

struct mem_pool
{
    uchar *mem_pool_addr;
    TAILQ_HEAD(, mem_chunk) free_chunk_list;
};
typedef struct mem_pool * mem_pool_t;

/* create memory pool */
mem_pool_t 
mem_pool_create(int chunk_size, int chunk_num, int is_hugepage);

/* allocate a chunk_size size chunk */
mem_chunk_t
mem_chunk_alloc(mem_pool_t mp);

/* free a chunk_size size chunk */
void 
mem_chunk_free(mem_pool_t mp, mem_chunk_t mc);

/* destroy memory pool */
void 
mem_pool_destroy(mem_pool_t mp);

uint32_t 
mem_pool_is_empty(mem_pool_t mp);

#endif /* __MEMPOOL_H__ */