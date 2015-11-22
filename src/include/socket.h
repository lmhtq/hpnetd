#ifndef __SOCKET_H_
#define __SOCKET_H_

/* socket type
 * it is the basic epoll, or listener or commom stream */
enum socket_type
{
    SOCK_UNUSED = 0,
    SOCK_STREAM,
    SOCK_LISTENER,
    SOCK_EPOLL
};

/* socket option */
enum socket_opts
{
    NON_BLOCK = 0,
    ADDR_BIND  
};

/* tcp listener */
struct tcp_listener
{
    int sockid;
    socket_t sk;

    int backlog;
    stream_queue_t acceptq;

    pthread_cond_t  accept_cond;
    pthread_mutex_t accept_lock;
};
typedef struct tcp_listener* tcp_listener_t;

/* socket map */
struct socket
{
    int id;
    int socktype;
    uint32_t opts;

    uint8_t valid;/* 1: in use, 0: can be reuse. */

    struct sockaddr_in saddr;
    
    union {
        tcp_stream_t stream;
        tcp_listener_t listener;
        mmutcpd_epoll_t ep;
    };

    uint32_t sockid; /* registered events (id) */
    uint32_t event_type; /* avaliable events (type)*/

};
typedef struct socket * socket_t;

/* socket queue */
struct socket_queue
{
    socket_t sockets;
    int start;
    int end;

    int size;
    int num_sockets;

    pthread_mutex_t socketq_lock;
};
typedef struct socket_queue * socket_queue_t;

/* init socket queue */
socket_queue_t 
init_socket_queue(int size);

/* free socket queue */
void
free_socket_queue(int cpu_id);

/* allocate a socket */
socket_t
allocate_socket(int cpu_id, int socktype);

/* free a socket */
void
free_socket(int cpu_id, int ep_id);


#endif /* __SOCKET_H_ */