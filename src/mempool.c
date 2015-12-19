#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/mman.h>

#include <mempool.h>

/* create memory pool */
mem_pool_t 
mem_pool_create(int chunk_size, int chunk_num, int is_hugepage)
{
    mem_pool_t  mp;
    size_t      total_size = chunk_size * chunk_num;
    int         i, j, res;
    uchar       *ptr;
    mem_chunk_t mc;

    mp = calloc(1, sizeof(struct mem_pool));
    if (!mp) {
        fprintf(stderr, 
            "calloc mp failed\n", );
        exit(0);
    }

    /* create big mem pool */
    res = posix_memalign(&mp->mem_pool_addr, getpagesize(), total_size);
    if (res) {
        fprintf(stderr, 
            "posix_memalign failed to create %ld mempool\n", total_size);
        assert(0);
        if (mp) 
            free(mp);
    }

    /* map them to the tailq */
    TAILQ_INIT(&mp->free_chunk_list);
    ptr = mp->mem_pool_addr;
    for (i = 0; i < chunk_num; i++) {
        mc = (struct mem_chunk*)calloc(1, sizeof(struct mem_chunk));
        mc->chunk_addr = ptr;
        TAILQ_INSERT_TAIL(&free_chunk_list, mc, mem_chunk->mem_chunk_link);
        ptr += chunk_size;
    }
}

/* allocate a chunk_size size chunk */
mem_chunk_t
mem_chunk_alloc(mem_pool_t mp)
{
    mem_chunk_t mc;
    mc = TAILQ_FIRST(&mp->free_chunk_list);
    TAILQ_REMOVE(&mp->free_chunk_list, mc, mem_chunk->mem_chunk_link);
    return mc;
}

/* free a chunk_size size chunk */
void 
mem_chunk_free(mem_pool_t mp, mem_chunk_t mc)
{
    TAILQ_INSERT_TAIL(&mp->free_chunk_list, mc, mem_chunk->mem_chunk_link);
    /* TODO: test insert head */
}

/* destroy memory pool */
void 
mem_pool_destroy(mem_pool_t mp)
{
    free(mp->mem_pool_addr);
    free(mp);
}

uint32_t 
mem_pool_is_empty(mem_pool_t mp)
{
    return TAILQ_EMPTY(&mp->free_chunk_list);
}