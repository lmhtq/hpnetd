#include "ringbuffer.h"

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))

/* send buffer part */
/* next index */
inline index_type 
next_index(send_buffer_queue_t sq, index_type i)
{
    return (i != sq->_capacity ? i + 1: 0);
}

/* prev index */
inline index_type 
prev_index(send_buffer_queue_t sq, index_type i)
{
    return (i != 0 ? i - 1: sq->_capacity);
}

/* memory barrier */
inline void 
send_buffer_mem_barrier(tcp_send_buffer_t volatile buf, volatile index_type index)
{
    __asm__ volatile("" : : "m" (buf), "m" (index));
}

/* create send buffer queue */
send_buffer_queue_t 
create_send_buffer_queue(int capacity)
{
    send_buffer_queue_t sq;

    sq = (send_buffer_queue_t)calloc(1, sizeof(struct send_buffer_queue));
    if (!sq)
        return NULL;

    sq->_q = (tcp_send_buffer_t *)
            calloc(capacity + 1, sizeof(struct tcp_send_buffer *));
    if (!sq->_q) {
        free(sq);
        return NULL;
    }

    sq->_capacity = capacity;
    sq->_head = sq->_tail = 0;

    return sq;
}

/* destroy send buffer queue */
void 
destroy_send_buffer_queue(send_buffer_queue_t sq)
{
    if (!sq)
        return;

    if (sq->_q) {
        free((void *)sq->_q);
        sq->_q = NULL;
    }

    free(sq);
}

/* put the buf to the send buffer queue's tail */
int 
send_buffer_enqueue_(send_buffer_queue_t sq, tcp_send_buffer_t buf)
{
    index_type h = sq->_head;
    index_type t = sq->_tail;
    index_type nt = next_index(sq, t);

    if (nt != h) {
        sq->_q[t] = buf;
        send_buffer_mem_barrier(sq->_q[t], sq->_tail);
        sq->_tail = nt;
        return 0;
    }

    fprintf(stderr, "Exceed capacity of buf queue!\n");
    return -1;
}

/* get one buf from the send buffer queue */
tcp_send_buffer_t
send_buffer_dequeue(send_buffer_queue_t sq)
{
    index_type h = sq->_head;
    index_type t = sq->_tail;

    if (h != t) {
        tcp_send_buffer_t buf = sq->_q[h];
        send_buffer_mem_barrier(sq->_q[h], sq->_head);
        sq->_head = next_index(sq, h);
        assert(buf);

        return buf;
    }

    return NULL;
}

/* get current num of send buffer queue */
uint32_t 
send_buffer_get_curnum(send_buffer_manager_t sbm)
{
    return sbm->cur_num;
}

/* create a buffer manager */
send_buffer_manager_t 
send_buffer_manager_create(size_t chunk_size, uint32_t cnum)
{
    send_buffer_manager_t sbm = (send_buffer_manager_t)calloc(1, 
        sizeof(struct send_buffer_manager));
    if (!sbm) {
        fprintf(stderr, "send_buffer_manager_create() failed. \n");
        return NULL;
    }

    sbm->chunk_size = chunk_size;
    sbm->cnum = cnum;
    sbm->mp = (mem_pool_t)mem_pool_create(chunk_size, (uint64_t)chunk_size * cnum, 0);
    if (!sbm->mp) {
        fprintf(stderr, "Failed to create mem pool for sb.\n");
        free(sbm);
        return NULL;
    }

    sbm->freeq = create_send_buffer_queue(cnum);
    if (!sbm->freeq) {
        fprintf(stderr, "Failed to create free buffer queue.\n");
        return NULL;
    }

    return sbm;
}

/* inti a tcp send buffer */
tcp_send_buffer_t
send_buffer_init(send_buffer_manager_t sbm, uint32_t init_seq)
{
    tcp_send_buffer_t buf;

    /* first try dequeue from free buffer queue */
    buf = send_buffer_dequeue(sbm->freeq);
    if (!buf) {
        buf = (tcp_send_buffer_t)malloc(sizeof(struct tcp_send_buffer));
        if (!buf) {
            perror("calloc() for buf");
            return NULL;
        }
        buf->data = mem_chunk_alloc(sbm->mp);
        if (!buf->data) {
            fprintf(stderr, "Failed to fetch memory chunk for data.\n");
            return NULL;
        }
        sbm->cur_num++;
    }

    buf->head = buf->data;

    buf->head_off = buf->tail_off = 0;
    buf->len = buf->cum_len = 0;
    buf->size = sbm->chunk_size;

    buf->init_seq = buf->head_seq = init_seq;
    
    return buf;
}

/* free the tcp send buffer */
void 
send_buffer_free(send_buffer_manager_t sbm, tcp_send_buffer_t buf)
{
    if (!buf)
        return;

    send_buffer_enqueue(sbm->freeq, buf);
}

/* put the tcp send buffer to the send buffer manager */
size_t 
send_buffer_put(send_buffer_manager_t sbm, tcp_send_buffer_t buf, 
    void *data, size_t len)
{
    size_t to_put;

    if (len <= 0)
        return 0;

    /* if no space, return -2 */
    to_put = MIN(len, buf->size - buf->len);
    if (to_put <= 0) {
        return -2;
    }

    if (buf->tail_off + to_put < buf->size) {
        /* if the data fit into the buffer, copy it */
        memcpy(buf->data + buf->tail_off, data, to_put);
        buf->tail_off += to_put;
    } else {
        /* if buffer overflows, move the existing payload and merge */
        memmove(buf->data, buf->head, buf->len);
        buf->head = buf->data;
        buf->head_off = 0;
        memcpy(buf->head + buf->len, data, to_put);
        buf->tail_off = buf->len + to_put;
    }
    buf->len += to_put;
    buf->cum_len += to_put;

    return to_put;
}

/* remove the tcp send buffer from the send buffer manager */
size_t 
send_buffer_remove(send_buffer_manager_t sbm, 
    tcp_send_buffer_t buf, size_t len)
{
    size_t to_remove;

    if (len <= 0)
        return 0;

    to_remove = MIN(len, buf->len);
    if (to_remove <= 0) {
        return -2;
    }

    buf->head_off += to_remove;
    buf->head = buf->data + buf->head_off;
    buf->head_seq += to_remove;
    buf->len -= to_remove;

    /* if buffer is empty, move the head to 0 */
    if (buf->len == 0 && buf->head_off > 0) {
        buf->head = buf->data;
        buf->head_off = buf->tail_off = 0;
    }

    return to_remove;
}


/* receive buffer part */

/* next index (recv buffer ) */
inline index_type
next_index_rb(recv_buffer_frag_queue_t rb_fragq, index_type i)
{
    return (i != rb_fragq->_capacity ? i + 1: 0);
}

/* prev index (recv buffer) */
inline index_type
prev_index_rb(recv_buffer_frag_queue_t rb_fragq, index_type i)
{
    return (i != 0 ? i - 1: rb_fragq->_capacity);
}

/* memory barrier */
inline void 
recv_buffer_frag_mem_barrier(fragment_ctx_t volatile frag, 
    volatile index_type index)
{
    __asm__ volatile("" : : "m" (frag), "m" (index));
}

/* create recv buffer fragment queue */
recv_buffer_frag_queue_t
create_recv_buffer_frag_queue(int capacity)
{
    recv_buffer_frag_queue_t rb_fragq;

    rb_fragq = (recv_buffer_frag_queue_t)calloc(1, 
        sizeof(struct recv_buffer_frag_queue));
    if (!rb_fragq)
        return NULL;

    rb_fragq->_q = (fragment_ctx_t *)
            calloc(capacity + 1, sizeof(fragment_ctx_t));
    if (!rb_fragq->_q) {
        free(rb_fragq);
        return NULL;
    }

    rb_fragq->_capacity = capacity;
    rb_fragq->_head = rb_fragq->_tail = 0;

    return rb_fragq;
}

/* destroy recv buffer frag queue */
void
destroy_recv_buffer_frag_queue(recv_buffer_frag_queue_t rb_fragq)
{
    if (!rb_fragq)
        return;

    if (rb_fragq->_q) {
        free((void *)rb_fragq->_q);
        rb_fragq->_q = NULL;
    }

    free(rb_fragq);
}

/* recv buffer frag enqueue */
int 
recv_buffer_frag_enqueue(recv_buffer_frag_queue_t rb_fragq, 
    fragment_ctx_t frag)
{
    index_type h = rb_fragq->_head;
    index_type t = rb_fragq->_tail;
    index_type nt = next_index_rb(rb_fragq, t);

    if (nt != h) {
        rb_fragq->_q[t] = frag;
        recv_buffer_frag_mem_barrier(rb_fragq->_q[t], rb_fragq->_tail);
        rb_fragq->_tail = nt;
        return 0;
    }

    fprintf(stderr, "Exceed capacity of frag queue!\n");
    return -1;
}

/* recv buffer frag dequeue */
fragment_ctx_t 
recv_buffer_frag_dequeue(recv_buffer_frag_queue_t rb_fragq)
{
    index_type h = rb_fragq->_head;
    index_type t = rb_fragq->_tail;

    if (h != t) {
        fragment_ctx_t frag = rb_fragq->_q[h];
        recv_buffer_frag_mem_barrier(rb_fragq->_q[h], rb_fragq->_head);
        rb_fragq->_head = next_index_rb(rb_fragq, h);
        assert(frag);

        return frag;
    }

    return NULL;
}

/* get current num */
uint32_t
recv_buffer_get_curnum(recv_buffer_manager_t rbm)
{
    return rbm->cur_num;
}

/* create a recv buffer manager */
recv_buffer_manager_t
recv_buffer_manager_create(size_t chunk_size, uint32_t cnum)
{
    recv_buffer_manager_t rbm = (recv_buffer_manager_t) calloc(1, 
        sizeof(struct recv_buffer_manager));

    if (!rbm) {
        perror("rbm_create calloc");
        return NULL;
    }

    rbm->chunk_size = chunk_size;
    rbm->cnum = cnum;
    rbm->mp = (mem_pool_t)mem_pool_create(chunk_size, (uint64_t)chunk_size * cnum, 0);
    if (!rbm->mp) {
        fprintf(stderr, "Failed to allocate mp pool.\n");
        free(rbm);
        return NULL;
    }

    rbm->frag_mp = (mem_pool_t)mem_pool_create(sizeof(struct fragment_ctx), 
                                    sizeof(struct fragment_ctx) * cnum, 0);
    if (!rbm->frag_mp) {
        fprintf(stderr, "Failed to allocate frag_mp pool.\n");
        mem_pool_destroy(rbm->mp);
        free(rbm);
        return NULL;
    }

    rbm->free_fragq = create_recv_buffer_frag_queue(cnum);
    if (!rbm->free_fragq) {
        fprintf(stderr, "Failed to create free fragment queue.\n");
        mem_pool_destroy(rbm->mp);
        mem_pool_destroy(rbm->frag_mp);
        free(rbm);
        return NULL;
    }
    rbm->free_fragq_int = create_recv_buffer_frag_queue(cnum);
    if (!rbm->free_fragq_int) {
        fprintf(stderr, "Failed to create internal free fragment queue.\n");
        mem_pool_destroy(rbm->mp);
        mem_pool_destroy(rbm->frag_mp);
        destroy_recv_buffer_frag_queue(rbm->free_fragq);
        free(rbm);
        return NULL;
    }

    return rbm;
}

/* free fragment context single  */
inline void
free_frag_context_single(recv_buffer_manager_t rbm, fragment_ctx_t frag)
{
    if (frag->is_calloc)
        free(frag);
    else    
        mem_chunk_free(rbm->frag_mp, frag);
}

/* free fragment context */
void 
free_frag_context(recv_buffer_manager_t rbm, fragment_ctx_t fctx)
{
    fragment_ctx_t remove;

    assert(fctx);
    if (fctx == NULL)   
        return;

    while (fctx) {
        remove = fctx;
        fctx = fctx->next;
        free_frag_context_single(rbm, remove);
    }
}

/* alloc fragment context */
fragment_ctx_t 
allocate_frag_context(recv_buffer_manager_t rbm)
{
    /* this function should be called only in mtcp thread */
    fragment_ctx_t frag;

    /* first try deqeue the fragment in free fragment queue */
    frag = recv_buffer_frag_dequeue(rbm->free_fragq);
    if (!frag) {
        frag = recv_buffer_frag_dequeue(rbm->free_fragq_int);
        if (!frag) {
            /* next fall back to fetching from mempool */
            frag = mem_chunk_alloc(rbm->frag_mp);
            if (!frag) {
                fprintf(stderr, "fragments depleted, fall back to calloc\n");
                frag = calloc(1, sizeof(struct fragment_ctx));
                if (frag == NULL) {
                    fprintf(stderr, "calloc failed\n");
                    exit(-1);
                }
                frag->is_calloc = 1; /* mark it as allocated by calloc */
            }
        }
    }
    memset(frag, 0, sizeof(*frag));
    return frag;
}

/* init a tcp recv buffer  */
tcp_recv_buffer_t 
recv_buffer_init(recv_buffer_manager_t rbm, uint32_t init_seq)
{
    tcp_recv_buffer_t buff = 
            (tcp_recv_buffer_t)calloc(1, sizeof(struct tcp_recv_buffer));

    if (buff == NULL){
        perror("rb_init buff");
        return NULL;
    }

    buff->data = mem_chunk_alloc(rbm->mp);
    if(!buff->data){
        perror("rb_init mem_chunk_alloc");
        return NULL;
    }

    //memset(buff->data, 0, rbm->chunk_size);

    buff->size = rbm->chunk_size;
    buff->head = buff->data;
    buff->head_seq = init_seq;
    buff->init_seq = init_seq;
    
    rbm->cur_num++;

    return buff;
}

/* free the tcp recv buffer */
recv_buffer_free(recv_buffer_manager_t rbm, tcp_recv_buffer_t buff)
{
    assert(buff);
    if (buff->fctx) {
        free_frag_context(rbm, buff->fctx);
        buff->fctx = NULL;
    }
    
    if (buff->data) {
        mem_chunk_free(rbm->mp, buff->data);
    }
    
    rbm->cur_num--;

    free(buff);
}

/* get min seq */
#define MAXSEQ ((uint32_t)(0xffffffff))
inline uint32_t 
get_min_seq(uint32_t a, uint32_t b)
{
    if (a == b) return a;
    if (a < b) 
        return ((b - a) <= MAXSEQ/2) ? a : b;
    /* b < a */
    return ((a - b) <= MAXSEQ/2) ? b : a;
}

/* get max seq */
inline uint32_t
get_max_seq(uint32_t a, uint32_t b)
{
    if (a == b) return a;
    if (a < b) 
        return ((b - a) <= MAXSEQ/2) ? b : a;
    /* b < a */
    return ((a - b) <= MAXSEQ/2) ? a : b;
}

/* whether two fragments can merge */
inline int 
can_merge(const fragment_ctx_t a, const fragment_ctx_t b)
{
    uint32_t a_end = a->seq + a->len + 1;
    uint32_t b_end = b->seq + b->len + 1;

    if (GetMinSeq(a_end, b->seq) == a_end ||
        GetMinSeq(b_end, a->seq) == b_end)
        return 0;
    return (1);
}

/* merge the two fragments */
inline void 
merge_frags(fragment_ctx_t a, fragment_ctx_t b)
{
    /* merge a into b */
    uint32_t min_seq, max_seq;

    min_seq = GetMinSeq(a->seq, b->seq);
    max_seq = GetMaxSeq(a->seq + a->len, b->seq + b->len);
    b->seq  = min_seq;
    b->len  = max_seq - min_seq;
}

/* put the recv buffer into the recv buffer manager */
int 
recv_buffer_put(recv_buffer_manager_t rbm, tcp_recv_buffer_t buff, 
    void* data uint32_t len, uint32_t cur_seq)
{
    int putx, end_off;
    fragment_ctx_t new_ctx;
    fragment_ctx_t iter;
    fragment_ctx_t prev;
    fragment_ctx_t pprev;
    int merged = 0;

    if (len <= 0)
        return 0;

    // if data offset is smaller than head sequence, then drop
    if (get_min_seq(buff->head_seq, cur_seq) != buff->head_seq)
        return 0;

    putx = cur_seq - buff->head_seq;
    end_off = putx + len;
    if (buff->size <= end_off) {
        return -2;
    }

    // if buffer is at tail, move the data to the first of head
    if (buff->size <= (buff->head_offset + end_off)) {
        memmove(buff->data, buff->head, buff->last_len + 1);
        buff->tail_offset -= buff->head_offset;
        buff->head_offset = 0;
        buff->head = buff->data;
    }
    //copy data to buffer
    memcpy(buff->head + putx, data, len);
    if (buff->tail_offset < buff->head_offset + end_off) 
        buff->tail_offset = buff->head_offset + end_off;
    buff->last_len = buff->tail_offset - buff->head_offset;
    buff->head[buff->last_len] = 0; /* null termination */

    // create fragmentation context blocks
    new_ctx = allocate_frag_context(rbm);
    if (!new_ctx) {
        perror("allocating new_ctx failed");
        return 0;
    }
    new_ctx->seq  = cur_seq;
    new_ctx->len  = len;
    new_ctx->next = NULL;

    // traverse the fragment list, and merge the new fragment if possible
    for (iter = buff->fctx, prev = NULL, pprev = NULL; 
        iter != NULL;
        pprev = prev, prev = iter, iter = iter->next) {
        
        if (can_merge(new_ctx, iter)) {
            /* merge the first fragment into the second fragment */
            merge_frags(new_ctx, iter);

            /* remove the first fragment */
            if (prev == new_ctx) {
                if (pprev)
                    pprev->next = iter;
                else
                    buff->fctx = iter;
                prev = pprev;
            }   
            free_frag_context_single(rbm, new_ctx);
            new_ctx = iter;
            merged = 1;
        } 
        else if (merged || 
                 get_max_seq(cur_seq + len, iter->seq) == iter->seq) {
            /* merged at some point, but no more mergeable
               then stop it now */
            break;
        } 
    }

    if (!merged) {
        if (buff->fctx == NULL) {
            buff->fctx = new_ctx;
        } else if (get_min_seq(cur_seq, buff->fctx->seq) == cur_seq) {
            /* if the new packet's seqnum is before the existing fragments */
            new_ctx->next = buff->fctx;
            buff->fctx = new_ctx;
        } else {
            /* if the seqnum is in-between the fragments or
               at the last */
            assert(get_min_seq(cur_seq, prev->seq + prev->len) ==
                   prev->seq + prev->len);
            prev->next = new_ctx;
            new_ctx->next = iter;
        }
    }
    if (buff->head_seq == buff->fctx->seq) {
        buff->cum_len += buff->fctx->len - buff->merged_len;
        buff->merged_len = buff->fctx->len;
    }
    
    return len;
}

/* remove the tcp recv buffer from the recv buffer */
size_t 
recv_buffer_remove(recv_buffer_manager_t rbm, tcp_recv_buffer_t buff, 
    size_t len, int option)
{
    /* this function should be called only in application thread */

    if (buff->merged_len < len) 
        len = buff->merged_len;
    
    if (len == 0) 
        return 0;

    buff->head_offset += len;
    buff->head = buff->data + buff->head_offset;
    buff->head_seq += len;

    buff->merged_len -= len;
    buff->last_len -= len;

    // modify fragementation chunks
    if (len == buff->fctx->len) {
        fragment_ctx_t remove = buff->fctx;
        buff->fctx = buff->fctx->next;
        if (option == AT_APP) {
            recv_buffer_frag_enqueue(rbm->free_fragq, remove);
        } else if (option == AT_MMUTCPD) {
            recv_buffer_frag_enqueue(rbm->free_fragq_int, remove);
        }
    } 
    else if (len < buff->fctx->len) {
        buff->fctx->seq += len;
        buff->fctx->len -= len;
    } 
    else {
        assert(0);
    }

    return len;
}
