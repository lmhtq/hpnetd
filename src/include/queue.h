#ifndef __QUEUE_H_
#define __QUEUE_H_

#include "stream.h"

#ifndef _INDEX_TYPE_
#define _INDEX_TYPE_
typedef uint32_t index_type;
typedef int32_t signed_index_type;
#endif

struct stream_queue
{
    index_type _capacity;
    volatile index_type _head;
    volatile index_type _tail;

    struct tcp_stream * volatile * _q;
};

typedef stream_queue * stream_queue_t;

typedef struct stream_queue_int
{
    tcp_stream_t *array;
    int size;

    int first;
    int last;
    int count;
} stream_queue_int;

typedef stream_queue_int * stream_queue_int_t;

/* create internal stream queue */
stream_queue_int_t
create_internal_stream_queue(int size);

/* destroy internal stream queue */
void 
destroy_internal_stream_queue(stream_queue_int_t sq);

/* internal stream enqueue */
int 
stream_internal_enqueue(stream_queue_int_t sq, tcp_stream_t stream);

/* internal stream dequeue */
tcp_stream_t
stream_internal_dequeue(stream_queue_int_t sq);

/* next index of stream queue */
inline index_type 
next_index_sq(stream_queue_t sq, index_type i);

/* prev index of stream queue */
inline index_type 
prev_index_sq(stream_queue_t sq, index_type i);

/* stream queue is empty */
int 
stream_queue_is_empty(stream_queue_t sq);

/* stream memory barrier */
inline void 
stream_mem_barrier(tcp_stream_t volatile stream, volatile index_type index);

/* create stream queue */
stream_queue_t 
create_stream_queue(int capacity);

/* destroy stream queue */
void 
destroy_stream_queue(stream_queue_t sq);

/* stream enqueue */
int 
stream_enqueue(stream_queue_t sq, tcp_stream_t stream);

/* stream dequeue */
tcp_stream_t 
stream_dequeue(stream_queue_t sq);

#endif /* __QUEUE_H_ */