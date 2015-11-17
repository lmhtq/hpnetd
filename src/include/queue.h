#ifndef __QUEUE_H_
#define __QUEUE_H_

#include "stream.h"

struct stream_queue
{
    uint32_t _capacity;
    volatile uint32_t _head;
    volatile uint32_t _tail;

    volatile tcp_stream_t *_q;
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

#endif /* __QUEUE_H_ */