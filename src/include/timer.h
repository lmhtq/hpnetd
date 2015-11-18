#ifndef __TIMER_H_
#define __TIMER_H_

#include "stream.h"

#define RTO_HASH 3000

struct rto_hashstore
{
    uint32_t rto_now_idx; /* pointing to the hs_table_s index */
    uint32_t rto_now_ts;  /*  */

    TAILQ_HEAD(rto_head, tcp_stream) rto_list[RTO_HASH];
};

#endif /* __TIMER_H_ */