#ifndef __ADDRPOOL_H_
#define __ADDRPOOL_H_

#include <netinet/in.h>
#include <sys/queue.h>

#define MIN_PORT (1025)
#define MAX_PORT (65535 + 1)

struct addr_entry
{
    struct sockaddr_in addr;
    TAILQ_ENTRY(addr_entry) addr_link;
};




#endif /* __ADDRPOOL_H_ */