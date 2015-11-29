#ifndef __SOCKET_H_
#define __SOCKET_H_

#include "queue.h"

struct tcp_listener
{
    int sockid;
    socket_map_t socket;

    int backlog;
    stream_queue_t acceptq;

    pthread_mutex_t accept_lock;
    pthread_cond_t accept_cond;

};

struct socket_map
{
    int id;
    int socktype;
    uint32_t opts;

    struct sockaddr_in saddr;

    union {
        struct tcp_stream   *stream;
        struct tcp_listener *listener;
        struct epoll        *ep;
        struct pipe         *pp;
    }

    uint32_t epoll;  /* registered events */
    uint32_t events; /* avaliable events */
    epoll_data_t ep_data;

    TAILQ_ENTRY(socket_map) free_smap_link;
};
typedef struct socket_map *socket_map_t;


#endif /* __SOCKET_H_ */