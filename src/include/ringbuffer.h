#ifndef __RINGBUFFER_H_
#define __RINGBUFFER_H_

/* send_buffer part */
#include <stdlib.h>
#include <stdint.h>

struct send_buffer_manager
{
    size_t chunk_size;
    uint32_t cur_num;
    uint32_t cnum;
    mem_pool_t mp;
    send_buffer_queue_t freeq;

};
typedef struct send_buffer_manager* send_buffer_manager_t;

struct tcp_send_buffer
{
    unsigned char *data;
    unsigned char *head;

    uint32_t head_off;
    uint32_t tail_off;
    uint32_t len;
    uint64_t cum_len;
    uint32_t size;

    uint32_t head_seq;
    uint32_t init_seq;
};
typedef struct tcp_send_buffer * tcp_send_buffer_t;

#ifndef _INDEX_TYPE_
#define _INDEX_TYPE_
typedef uint32_t index_type;
typedef int32_t signed_index_type;
#endif

struct send_buffer_queue
{
    index_type _capacity;
    volatile index_type _head;
    volatile index_type _tail;

    tcp_send_buffer_t volatile * _q;
};
typedef struct send_buffer_queue * send_buffer_queue_t;

/* next index */
inline index_type 
next_index(send_buffer_queue_t sq, index_type i);

/* prev index */
inline index_type 
prev_index(send_buffer_queue_t sq, index_type i);

/* memory barrier */
inline void 
send_buffer_mem_barrier(tcp_send_buffer_t volatile buf, 
    volatile index_type index);

/* create send buffer queue */
send_buffer_queue_t 
create_send_buffer_queue(int capacity);

/* destroy send buffer queue */
void 
destroy_send_buffer_queue(send_buffer_queue_t sq);

/* put the buf to the send buffer queue's tail */
int 
send_buffer_enqueue(send_buffer_queue_t sq, tcp_send_buffer_t buf);

/* get one buf from the send buffer queue */
tcp_send_buffer_t
send_buffer_dequeue(send_buffer_queue_t sq);

/* get current num of send buffer queue */
uint32_t 
send_buffer_get_curnum(send_buffer_manager_t sbm);

/* create a buffer manager */
send_buffer_manager_t 
send_buffer_manager_create(size_t chunk_size, uint32_t cnum);

/* inti a tcp send buffer */
tcp_send_buffer_t
send_buffer_init(send_buffer_manager_t sbm, uint32_t init_seq);

/* free the tcp send buffer */
void 
send_buffer_free(send_buffer_manager_t sbm, tcp_send_buffer_t buf);

/* put the tcp send buffer to the send buffer manager */
size_t 
send_buffer_put(send_buffer_manager_t sbm, tcp_send_buffer_t buf, void *data, size_t len);

/* remove the tcp send buffer from the send buffer manager */
size_t 
send_buffer_remove(send_buffer_manager_t sbm, tcp_send_buffer_t buf, size_t len);


/* receive buffer part */
enum recv_buffer_caller
{
    AT_APP, 
    AT_MMUTCPD
};

struct fragment_ctx
{
    uint32_t seq;
    uint32_t len : 31;
    uint32_t is_calloc : 1;
    struct fragment_ctx *next;
};
typedef struct fragment_ctx * fragment_ctx_t;

struct recv_buffer_frag_queue
{
    index_type _capacity;
    volatile index_type _head;
    volatile index_type _tail;

    fragment_ctx_t volatile * _q;
};
typedef struct recv_buffer_frag_queue * recv_buffer_frag_queue_t;


struct tcp_recv_buffer
{
    u_char* data;           /* buffered data */
    u_char* head;           /* pointer to the head */

    uint32_t head_offset;   /* offset for the head (head - data) */
    uint32_t tail_offset;   /* offset fot the last byte (null byte) */

    int merged_len;         /* contiguously merged length */
    uint64_t cum_len;       /* cummulatively merged length */
    int last_len;           /* currently saved data length */
    int size;               /* total ring buffer size */
    
    /* TCP payload features */
    uint32_t head_seq;
    uint32_t init_seq;

    fragment_ctx_t fctx;
};
typedef struct tcp_recv_buffer * tcp_recv_buffer_t;

struct recv_buffer_manager
{
    size_t chunk_size;
    uint32_t cur_num;
    uint32_t cnum;

    mem_pool_t mp;
    mem_pool_t frag_mp;

    recv_buffer_frag_queue_t free_fragq;     /* free fragment queue (for app thread) */
    recv_buffer_frag_queue_t free_fragq_int; /* free fragment quuee (only for mtcp) */

};
typedef struct recv_buffer_manager * recv_buffer_manager_t;

/* next index (recv buffer ) */
inline index_type
next_index_rb(recv_buffer_frag_queue_t rb_fragq, index_type i);

/* prev index (recv buffer) */
inline index_type
prev_index_rb(recv_buffer_frag_queue_t rb_fragq, index_type i);

/* memory barrier */
inline void 
recv_buffer_frag_mem_barrier(fragment_ctx_t volatile frag, 
    volatile index_type index);

/* create recv buffer fragment queue */
recv_buffer_frag_queue_t
create_recv_buffer_frag_queue(int capacity);

/* destroy recv buffer frag queue */
void
destroy_recv_buffer_frag_queue(recv_buffer_frag_queue_t rb_fragq);

/* recv buffer frag enqueue */
int 
recv_buffer_frag_enqueue(recv_buffer_frag_queue_t rb_fragq, 
    fragment_ctx_t frag);

/* recv buffer frag dequeue */
fragment_ctx_t 
recv_buffer_frag_dequeue(recv_buffer_frag_queue_t rb_fragq);

/* get current num */
uint32_t
recv_buffer_get_curnum(recv_buffer_manager_t rbm);

/* create a recv buffer manager */
recv_buffer_manager_t
recv_buffer_manager_create(size_t chunk_size, uint32_t cnum);

/* free fragment context single  */
inline void
free_frag_context_single(recv_buffer_manager_t rbm, fragment_ctx_t frag);

/* free fragment context */
void 
free_frag_context(recv_buffer_manager_t rbm, fragment_ctx_t fctx);

/* alloc fragment context */
fragment_ctx_t 
allocate_frag_context(recv_buffer_manager_t rbm);

/* init a tcp recv buffer  */
tcp_recv_buffer_t 
recv_buffer_init(recv_buffer_manager_t rbm, uint32_t init_seq);

/* free the tcp recv buffer */
recv_buffer_free(recv_buffer_manager_t rbm, tcp_recv_buffer_t buff);

/* get min seq */
#define MAXSEQ ((uint32_t)(0xffffffff))
inline uint32_t 
get_min_seq(uint32_t a, uint32_t b);

/* get max seq */
inline uint32_t
get_max_seq(uint32_t a, uint32_t b);

/* whether two fragments can merge */
inline int 
can_merge(const fragment_ctx_t a, const fragment_ctx_t b);

/* merge the two fragments */
inline void 
merge_frags(fragment_ctx_t a, fragment_ctx_t b);

/* put the recv buffer into the recv buffer manager */
int 
recv_buffer_put(recv_buffer_manager_t rbm, tcp_recv_buffer_t buff, 
    void* data uint32_t len, uint32_t cur_seq);

/* remove the tcp recv buffer from the recv buffer */
size_t 
recv_buffer_remove(recv_buffer_manager_t rbm, tcp_recv_buffer_t buff, 
    size_t len, int option);

#endif /* __RINGBUFFER_H_ */