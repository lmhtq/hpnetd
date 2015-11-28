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

    uint32_t epoll;  /* registered events */
    uint32_t events; /* avaliable events  */
    epoll_data_t ep_data;

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


/* api's */
/* is connected */
inline int
mmutcpd_is_connected(mmutcpd_manager_t mmt, tcp_stream_t cur);

/* get socket error */
inline int 
mmutcpd_get_socket_error(socket_map_t sk, void *optval, socklen_t *optlen);

/* get sockopt */
int 
mmutcpd_getsockopt(int cpu_id, int sockid, int level, 
    int optname, void *optval, socklen_t *optlen);

/* set sockopt */
int
mmutcpd_setsockopt(int cpu_id, int sockid, int level, 
    int optname, const void *optval, socklen_t optlen);

/* set sock nonblock */
int
mmutcpd_setsock_nonblock(int cpu_id, int sockid);

/* socket ioctl */
int 
mmutcpd_socket_ioctl(int cpu_id, int sockid, int request, void *argp);

/* create a socket */
int 
mmutcpd_socket(int cpu_id, int domain, int type, int protocol);

/* socket bind */
int 
mmutcpd_bind(int cpu_id, int sockid, const struct sockaddr *addr, 
    socklen_t addrlen);

/* socket listen */
int 
mmutcpd_listen(int cpu_id, int sockid, int backlog);

/* socket accept */
int 
mmutcpd_accept(int cpu_id, int sockid, struct sockaddr *addr, 
    socklen_t *addrlen);

/* TODO: init rss */
/* TODO: get_rss_cpu_core */
int 
get_rss_cpu_core(in_addr_t sip, in_addr_t dip, in_port_t sp, 
    in_port_t dp, int num_queues);

/* socket connect */
int 
mmutcpd_connect(int cpu_id, int sockid, const struct sockaddr *addr, 
    socklen_t addrlen);

/* close stream close */
inline int 
close_stream_socket(int cpu_id, int sockid);

/* close listening socket */
inline int 
close_listening_socket(int cpu_id, int sockid);

/* close socket */
int 
mmutcpd_close(int cpu_id, int sockid);

/* abort socket */
int 
mmutcpd_abort(int cpu_id, int sockid);

/* read socket */
int 
mmutcpd_read(int cpu_id, int sockid, char *buf, int len);

/* readv socket */
int 
mmutcpd_readv(int cpu_id, int sockid, struct iovec *iov, int iov_num);

/* copy data to app */
inline int 
cp_to_app(int cpu_id, tcp_stream_t cur, char *buf, int len);

/* write socket */
int 
mmutcpd_write(int cpu_id, int sockid, char *buf, int len);

/* writev socket */
int 
mmutcpd_writev(int cpu_id, int sockid, struct iovec *iov, int iov_num);

/* copy data from app */
inline int 
cp_from_app(int cpu_id, tcp_stream_t cur, char *buf, int len);

#endif /* __SOCKET_H_ */