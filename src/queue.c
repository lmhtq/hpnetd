#include "queue.h"

/* create internal stream queue */
stream_queue_int_t
create_internal_stream_queue(int size)
{
    stream_queue_int_t sq;

    sq = (stream_queue_int_t)calloc(1, sizeof(stream_queue_int));
    if (!sq) {
        return NULL;
    }

    sq->array = (tcp_stream_t *)calloc(size, sizeof(tcp_stream *));
    if (!sq->array) {
        free(sq);
        return NULL;
    }

    sq->size = size;
    sq->first = sq->last = 0;
    sq->count = 0;

    return sq;
}

/* destroy internal stream queue */
void 
destroy_internal_stream_queue(stream_queue_int_t sq)
{
    if (!sq)
        return;
    
    if (sq->array) {
        free(sq->array);
        sq->array = NULL;
    }

    free(sq);
}

/* internal stream enqueue */
int 
stream_internal_enqueue(stream_queue_int_t sq, tcp_stream_t stream)
{
    if (sq->count >= sq->size) {
        /* queue is full */
        printf("[WARNING] Queue overflow. Set larger queue size! "
                "count: %d, size: %d\n", sq->count, sq->size);
        return -1;
    }

    sq->array[sq->last++] = stream;
    sq->count++;
    if (sq->last >= sq->size) {
        sq->last = 0;
    }
    assert (sq->count <= sq->size);

    return 0;
}

/* internal stream dequeue */
tcp_stream_t
stream_internal_dequeue(stream_queue_int_t sq)
{
    tcp_stream_t stream = NULL;

    if (sq->count <= 0) {
        return NULL;
    }

    stream = sq->array[sq->first++];
    assert(stream != NULL);
    if (sq->first >= sq->size) {
        sq->first = 0;
    }
    sq->count--;
    assert(sq->count >= 0);

    return stream;
}

/* next index of stream queue */
inline index_type 
next_index_sq(stream_queue_t sq, index_type i)
{
    return (i != sq->_capacity ? i + 1: 0);
}

/* prev index of stream queue */
inline index_type 
prev_index_sq(stream_queue_t sq, index_type i)
{
    return (i != 0 ? i - 1: sq->_capacity);
}

/* stream queue is empty */
int 
stream_queue_is_empty(stream_queue_t sq)
{
    return (sq->_head == sq->_tail);
}

/* stream memory barrier */
inline void 
stream_mem_barrier(tcp_stream_t volatile stream, volatile index_type index)
{
    __asm__ volatile("" : : "m" (stream), "m" (index));
}

/* create stream queue */
stream_queue_t 
create_stream_queue(int capacity)
{
    stream_queue_t sq;

    sq = (stream_queue_t)calloc(1, sizeof(struct stream_queue));
    if (!sq)
        return NULL;

    sq->_q = (tcp_stream_t *)calloc(capacity + 1, sizeof(tcp_stream *));
    if (!sq->_q) {
        free(sq);
        return NULL;
    }

    sq->_capacity = capacity;
    sq->_head = sq->_tail = 0;

    return sq;
}

/* destroy stream queue */
void 
destroy_stream_queue(stream_queue_t sq)
{
    if (!sq)
        return;

    if (sq->_q) {
        free((void *)sq->_q);
        sq->_q = NULL;
    }

    free(sq);
}

/* stream enqueue */
int 
stream_enqueue(stream_queue_t sq, tcp_stream_t stream)
{
    index_type h = sq->_head;
    index_type t = sq->_tail;
    index_type nt = next_index_sq(sq, t);

    if (nt != h) {
        sq->_q[t] = stream;
        stream_mem_barrier(sq->_q[t], sq->_tail);
        sq->_tail = nt;
        return 0;
    }

    fprintf(stderr, "Exceed capacity of stream queue!\n");
    return -1;
}

/* stream dequeue */
tcp_stream_t 
stream_dequeue(stream_queue_t sq)
{
    index_type h = sq->_head;
    index_type t = sq->_tail;

    if (h != t) {
        tcp_stream_t stream = sq->_q[h];
        stream_mem_barrier(sq->_q[h], sq->_head);
        sq->_head = next_index_sq(sq, h);
        assert(stream);
        return stream;
    }

    return NULL;
}
