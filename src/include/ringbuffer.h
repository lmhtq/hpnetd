#ifndef __RINGBUFFER_H_
#define __RINGBUFFER_H_

#include "rte_malloc.h"

struct buffer_queue
{
    uint8_t *buffers;
    int start,
    int end;

    int size;
    int num_buffers   
};

#endif /* __RINGBUFFER_H_ */