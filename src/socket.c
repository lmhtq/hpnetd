#include "socket.h"

/* init socket queue */
socket_queue_t 
init_socket_queue(int size)
{
    socket_queue_t skq;

    skq = (socket_queue_t)calloc(1, sizeof(struct socket_queue));
    if (!skq) {
        return NULL;
    }

    skq->start = skq->end = 0;
    skq->size = size;
    skq->sockets = (socket_t)calloc(size, sizeof(struct socket));
    if (!skq->sockets) {
        free(skq);
        return NULL;
    }
    skq->num_sockets = 0;

    if (pthread_mutex_init(&skq->socketq_lock, NULL)) {
        return -1;
    }

    return skq;
}


/* free socket queue */
void
free_socket_queue(socket_queue_t skq)
{
    if (skq->sockets) 
        free(skq->sockets);
    
    free(skq);
}

/* allocate a socket and init it */
socket_t
allocate_socket(int cpu_id, int socktype, int needlock)
{
    mmutcpd_manager_t mmt = g_mmutcpd[cpu_id];
    socket_queue_t skq;
    socket_t sk;

    skq = mmt->socketq;

    pthread_mutex_lock(skq->socketq_lock);

    if (skq->num_sockets >= skq->size - 1) {
        
        fprintf(stderr, "Socket queue full!"
            "%s:%s\n", __FILE__, __LINE__));
        pthread_mutex_unlock(&skq->socketq_lock);
        return NULL;
    }

    skq->end++;
    if (skq >= skq->size) {
        skq->end = 0;
    }
    skq->num_sockets++;

    sk = &skq[skq->end];
    sk.id = skq->end;
    sk.socktype = socktype;
    sk.opts = 0;
    sk.valid = 1;
    sk.epoll = 0;
    sk.events = 0;
    memset(&sk->ep_data, 0, sizeof(epoll_data_t));

    pthread_mutex_unlock(&skq->socketq_lock);

    return sk;
}


/* free a socket */
void
free_socket(int cpu_id, int ep_id)
{
    mmutcpd_manager_t mmt = g_mmutcpd[cpu_id];
    socket_queue_t skq;
    socket_t sk;
    int i = ep_id;
    int left;

    pthread_mutex_lock(&socketq_lock);

    skq = mmt->socketq;
    sk = &skq[ep_id];
    memset(sk, 0, sizeof(struct socket));
    skq->num_sockets--;

    /* TODO: optimize it later */
    /* This is to determine the queue's new left edge.
     * The left edge  */
    left = skq->start;
    if (i == left) {
        skq->start++;
        pthread_mutex_unlock(&socketq_lock);
        return;
    }

    if (i > left) {
        for (; i > left; i-- ) {
            if (skq[i].valid) {
                pthread_mutex_unlock(&socketq_lock);
                return;
            }
        }
    } else {
        for (; i > 0; i--) {
            if (skq[i].valid) {
                pthread_mutex_unlock(&socketq_lock);
                return;
            }
        }

        for (i = skq->size-1; i > left; i--) {
            if (skq[i].valid) {
                pthread_mutex_unlock(&socketq_lock);
                return;
            }
        }

    }

    skq->start = ep_id;

    pthread_mutex_unlock(&socketq_lock);

    return;
}



/* api's */
/* is connected */
inline int
mmutcpd_is_connected(mmutcpd_manager_t mmt, tcp_stream_t cur)
{
    if (!cur || cur->state != TCP_ESTABLISHED) {
        return FALSE;
    }

    return TRUE;
}

/* get socket error */
inline int 
get_socket_error(socket_map_t sk, void *optval, socklen_t *optlen)
{
    tcp_stream_t cur;

    if (!sk->stream) {
        errno = EBADF;
        return -1;
    }

    cur = sk->stream;
    if (cur->state == TCP_CLOSE) {
        if (cur->close_reason == TCP_TIMEOUT ||
            cur->close_reason == TCP_CONN_FAIL ||
            cur->close_reason == TCP_CONN_LOST) {
            *(int *)optval = ETIMEDOUT;
            *optlen = sizeof(int);

            return 0;
        }
    }

    if (cur->state == TCP_CLOSE_WAIT ||
        cur->state == TCP_CLOSE) {
        if (cur->close_reason == TCP_RESET) {
            *(int *)optval = ECONNRESET;
            *optlen = sizeof(int);

            return 0;
        }
    }

    errno = ENOSYS;
    return -1;

}


/* get sockopt */
int 
mmutcpd_getsockopt(int cpu_id, int sockid, int level, 
    int optname, void *optval, socklen_t *optlen)
{
    mmutcpd_manager_t mmt[cpu_id];
    socket_map_t      sk;

    if (sockid < 0 || sockid >= m_config.max_concurrency) {
        fprintf(stderr, 
            "Socket id %d out of range.\n", sockid);
        errno = EBADF;
        return -1;
    }

    sk = &mmt->socketq[sockid];
    if (sk->socktype == SOCK_UNUSED) {
        fprintf(stderr, 
            "Invalid socket id %d\n", sockid);
        errno = EBADF;
        return -1;
    }

    if (sk->socktype != SOCK_LISTENER && sk->socktype != SOCK_STREAM) {
        fprintf(stderr, 
            "Not a stream socket id %d\n", sockid);
        errno = EBADF;
        return -1;
    }

    if (level == SOL_SOCKET) {
        if (optname == SO_ERROR) {
            if (sk->socktype == SOCK_STREAM) {
                return mmutcpd_get_socket_error(sk, optval, optlen);
            }
        }
    }

    errno = ENOSYS;
    return -1;
}


/* set sockopt */
int
mmutcpd_setsockopt(int cpu_id, int sockid, int level, 
    int optname, const void *optval, socklen_t optlen)
{
    mmutcpd_manager_t mmt = g_mmutcpd[cpu_id];
    socket_map_t      sk;

    if (sockid < 0 || sockid >= m_config.max_concurrency) {
        fprintf(stderr, 
            "Socket id %d out of range.\n", sockid);
        errno = EBADF;
        return -1;
    }

    sk = &mmt->socketq[sockid];
    if (sk->socktype == SOCK_UNUSED) {
        fprintf(stderr, 
            "Invalid socket id %d\n", sockid);
        errno = EBADF;
        return -1;
    }

    if (sk->socktype != SOCK_LISTENER && sk->socktype != SOCK_STREAM) {
        fprintf(stderr, 
            "Not a stream socket id %d\n", sockid);
        errno = EBADF;
        return -1;
    }

    return 0;
}


/* set sock nonblock */
int
mmutcpd_setsock_nonblock(int cpu_id, int sockid)
{
    mmutcpd_manager_t mmt = g_mmutcpd[cpu_id];
    socket_map_t      sk;

    if (sockid < 0 || sockid >= m_config.max_concurrency) {
        fprintf(stderr, 
            "Socket id %d out of range.\n", sockid);
        errno = EBADF;
        return -1;
    }

    sk = &mmt->socketq[sockid];
    if (sk->socktype == SOCK_UNUSED) {
        fprintf(stderr, 
            "Invalid socket id %d\n", sockid);
        errno = EBADF;
        return -1;
    }

    sk->socketq[sockid].opts |= NON_BLOCK;

    return 0;
}


/* socket ioctl */
int 
mmutcpd_socket_ioctl(int cpu_id, int sockid, int request, void *argp)
{
    mmutcpd_manager_t mmt = g_mmutcpd[cpu_id];
    socket_map_t      sk;
    tcp_stream_t      cur;
    tcp_ring_buffer_t rbuf;

    if (sockid < 0 || sockid >= m_config.max_concurrency) {
        fprintf(stderr, 
            "Socket id %d out of range.\n", sockid);
        errno = EBADF;
        return -1;
    }

    sk = &mmt->socketq[sockid];
    /* must be stream socket */
    if (sk->socktype != SOCK_STREAM) {
        fprintf(stderr, 
            "Invalid socket id %d\n", sockid);
        errno = EBADF;
        return -1;
    }

    if (!argp) {
        errno = EFAULT;
        return -1;
    }

    if (request == FIONREAD) {
        cur = sk->stream;
        if (!cur) {
            errno = EBADF
            return -1;
        }

        rbuf = cur->rcv_var->rcvbuf;
        if (rbuf) {
            *(int *)argp = rbuf->merged_len;
        } else {
            *(int I)argp = 0;
        }
    } else {
        errno = EINVAL;
        return -1;
    }

    return 0;
}


/* create a socket */
int 
mmutcpd_socket(int cpu_id, int domain, int type, int protocol)
{
    mmutcpd_manager_t mmt = g_mmutcpd[cpu_id];
    socket_map_t      sk;

    if (!mmt) {
        errno = ENFILE;
        return -1
    }

    if (domain != AF_INET) {
        errno = EAFNOSUPPORT;
        return -1
    }

    if (type == SOCK_STREAM) {
        type = SOCK_STREAM;
    } else {
        errno = EINVAL;
        return -1;
    }

    sk = allocate_socket(cpu_id, type, FALSE);
    if (!sk) {
        errno = ENFILE;
        return -1;
    }

    return sk->id;
}


/* socket bind */
int 
mmutcpd_bind(int cpu_id, int sockid, const struct sockaddr *addr, 
    socklen_t addrlen)
{
    mmutcpd_manager_t  mmt = g_mmutcpd[cpu_id];
    socket_map_t       sk;
    struct sockaddr_in *addr_in;

    if (!mmt) {
        return -1;
    }

    if (sockid < 0 || sockid >= m_config.max_concurrency) {
        fprintf(stderr, 
            "Socket id %d out of range.\n", sockid);
        errno = EBADF;
        return -1;
    }

    sk = &mmt->socketq[sockid];
    if (sk->socktype == SOCK_UNUSED) {
        fprintf(stderr, 
            "Invalid socket id %d\n", sockid);
        errno = EBADF;
        return -1;
    }

    if (sk->socktype != SOCK_LISTENER && sk->socktype != SOCK_STREAM) {
        fprintf(stderr, 
            "Not a stream socket id %d\n", sockid);
        errno = EBADF;
        return -1;
    }

    if (!addr) {
        fprintf(stderr, 
            "Socket id %d: empty address.\n", sockid);
        errno = EINVAL;
        return -2;
    }

    if (sk->opts & ADDR_BIND) {
        fprintf(stderr, 
            "Socket id %d address already bind for this socket.\n", sockid);
        errno = EINVAL;
        return -1;
    }

    /* just support AF_INET */
    if (addr->sa_family != AF_INET || addrlen < sizeof(struct sockaddr_in)) {
        fprintf(stderr, 
            "Socket id %d: invalid arguments\n", sockid);
        errno = EINVAL;
        return -1;
    }

    /* TODO: check whether the address is in use */

    addr_in = (struct sockaddr_in*)addr;
    sk.saddr = *addr_in;
    sk.opts |= ADDR_BIND;

    return 0;
}


/* socket listen */
int 
mmutcpd_listen(int cpu_id, int sockid, int backlog)
{
    mmutcpd_manager_t mmt = g_mmutcpd[cpu_id];
    socket_map_t      sk;
    tcp_listener_t    listener;

    if (!mmt) {
        return -1;
    }

    if (sockid < 0 || sockid >= m_config.max_concurrency) {
        fprintf(stderr, 
            "Socket id %d out of range.\n", sockid);
        errno = EBADF;
        return -1;
    }

    sk = &mmt->socketq[sockid];
    if (sk->socktype == SOCK_UNUSED) {
        fprintf(stderr, 
            "Invalid socket id %d\n", sockid);
        errno = EBADF;
        return -1;
    }

    if (sk->socktype == SOCK_STREAM) {
        sk.socktype = SOCK_LISTENER;
    }

    if (sk->socktype != SOCK_LISTENER) {
        fprintf(stderr, 
            "Not a listening socket id %d\n", sockid);
        errno = EBADF;
        return -1;
    }

    if (backlog <= 0 || backlog > m_config.max_concurrency) {
        errno = EINVAL;
        return -1;
    }

    listener = (tcp_listener_t)calloc(1, sizeof(struct tcp_listener));
    if (!listener) {
        errno = EINVAL;
        return -1;
    }

    listener->sockid =sockid;
    listener->backlog = backlog;
    listener->socket = sk;

    if (pthread_cond_init(&listener->accept_cond, NULL)) {
        perror("pthread_cond_init of listener->accept_cond\n");
        return -1;
    }

    if (pthread_mutex_init(&listener->accept_lock, NULLULL)) {
        perror("pthread_mutex_init of listener->accept_lock\n");
        return -1;
    }

    listener->acceptq = create_stream_queue(backlog);
    if (!listener->acceptq) {
        errno = ENOMEM;
        return -1;
    }

    sk.listener = listener;
    mmt->listener = listener;

    return 0;
}


/* socket accept */
/* origin accept() */
/* addr: the client side addr  */
int 
mmutcpd_accept(int cpu_id, int sockid, struct sockaddr *addr, 
    socklen_t *addrlen)
{
    mmutcpd_manager_t  mmt = g_sender[cpu_id];
    socket_map_t       sk;
    tcp_listener_t     listener;
    tcp_stream_t       accepted = NULL;
    struct sockaddr_in *addr_in;

    if (!mmt) {
        return -1;
    }

    if (sockid < 0 || sockid >= m_config.max_concurrency) {
        fprintf(stderr, 
            "Socket id %d out of range.\n", sockid);
        errno = EBADF;
        return -1;
    }

    sk = &mmt->socketq[sockid];
    if (sk->socktype != SOCK_LISTENER) {
        fprintf(stderr, 
            "Socket id %d is not listening socket\n", sockid);
        errno = EINVAL;
        return -1;
    }

    listener = sk.listener;

    /* try to directly get the first item of accept queue without lock */
    /* if get nothing, require lock and wait */
    accepted = stream_dequeue(listener->acceptq);
    if (!accepted) {
        if (listener->sk->opts & NON_BLOCK) {
            errno = EAGAIN;
            return -1;
        } else {
            pthread_mutex_lock(&listener->accept_lock);
            while ((accepted = stream_dequeue(listener->acceptq)) == NULL) {
                pthread_cond_wait(&listener->accept_cond, 
                    &listener->accept_lock);
                if (mmt->ctx->done || mmt->ctx->exit) {
                    pthread_mutex_unlock(&listener->accept_lock);
                    errno = EINTR;
                    return -1;   
                }
            }
            pthread_mutex_unlock(&listener->accept_lock);
        }
    }

    if (!accepted) {
        fprintf(stderr, 
            "Empty accept queue!\n", );
    }

    if (!accepted->sk) {
        sk = allocate_socket(cpu_id, SOCK_STREAM, FALSE);
        if (!sk) {
            /* TODO: destroy the stream */
            errno = ENFILE;
            return -1;
        }
        sk->stream = accepted;
        accepted->sk = sk;
    }

    /*TODO: trace info*/

    if (addr && addrlen) {
        addr_in = (struct sockaddr_in *)addr;
        addr_in->sin_family = AF_INET;
        addr_in->sin_port = accepted->dport;
        addr_in->sin_addr.s_addr = accepted->daddr;
        *addrlen = sizeof(struct sockaddr_in);
    }

    return accepted->sk->id;
}


/* socket connect */
int 
mmutcpd_connect(int cpu_id, int sockid, const struct sockaddr *addr, 
    socklen_t addrlen)
{
    mmutcpd_manager_t  mmt = g_mmutcpd[cpu_id];
    socket_map_t       sk;
    tcp_stream_t       cur;
    struct sockaddr_in *addr_in;
    in_addr_t          dip;
    in_port_t          dport;
    int                is_dyn_bound = FALSE;
    int                ret;
    int                rss_core;

    if (!mmt) {
        return -1;
    }

    if (sockid < 0 || sockid >= m_config.max_concurrency) {
        fprintf(stderr, 
            "Socket id %d out of range.\n", sockid);
        errno = EBADF;
        return -1;
    }

    sk = &mmt->socketq[sockid];
    if (sk->socktype == SOCK_UNUSED) {
        fprintf(stderr, 
            "Invalid socket id %d\n", sockid);
        errno = EBADF;
        return -1;
    }

    if (sk->socktype != SOCK_STREAM) {
        fprintf(stderr, 
            "Socket id %d is not a stream socket\n", sockid);
        errno = ENOTSCOK;
        return -1;
    }

    if (!addr) {
        fprintf(stderr, 
            "Socket id %d, empty address.\n", sockid);
        errno = EFAULT;
        return -1;
    }

    /* just support AF_INET */
    if (addr->sa_family != AF_INET || 
        addrlen < sizeof(struct sockaddr_in)) {
        fprintf(stderr, 
            "Socket id %d: invalid arguments\n", sockid);
        errno = EAFNOSUPPORT;
        return -1;
    }

    sk = &mmt->socketq[sockid];
    if (sk->stream) {
        fprintf(stderr, 
            "Socket id %d, stream already exist.\n", sockid);
        if (sk->stream->state >= TCP_ESTABLISHED) {
            errno = EISCONN;
        } else {
            errno = EALREADY;
        }
        return -1;
    }

    addr_in = (struct sockaddr_in *)addr;
    dip = addr_in.s_addr;
    dport = addr_in.sin_port;

    /* address binding */
    if (sk->opts & ADDR_BIND) {
        /* TODO: */
        rss_core = get_rss_cpu_core(sk->sin_addr.s_addr, dip,
            sk->saddr.sin_port, dport, num_queues);
        if (rss_core != cpu_id) {
            errno = EINVAL;
            return -1;
        }
    } else {
        /* TODO: address_pool */
        if (mmt->ap) {
            ret = fetch_address(mmt->ap, cpu_id, 
                num_queues, addr_in, &sk->saddr);
        } else {
            ret = fetch_address(mmt->ap, cpu_id, 
                num_queues, addr_in, &sk->saddr);
        }

        if (ret < 0) {
            errno = EAGAIN;
            return -1;
        }
        sk->opts |= ADDR_BIND;
        is_dyn_bound = TRUE;
    }

    cur = create_tcp_stream(mmt, sk, sk->socktype, 
        sk->saddr.sin_addr.s_addr, sk->saddr.sin_port, dip, dport);
    if (!cur) {
        fprintf(stderr, 
            "Socket id %s, failed to create tcp stream\n", sockid);
        errno = ENOMEM;
        return -1;
    }

    if (is_dyn_bound) {
        cur->is_bound_addr = TRUE;
    }

    /* tcp stream snd_var */
    cur->snd_var->cwnd = 1;
    cur->snd_var->ssthresh = cur->snd_var->mss * 10;

    /* tcp stream state */
    cur->state = TCP_SYN_SENT;

    /* TODO: stream queue lock? */
    ret = stream_enqueue(mmt->connectq, cur);
    mmt->wakeup_flag = TRUE;
    if (ret < 0) {
        fprintf(stderr, 
            "Socket id %d, failed to enqueue to connectq\n", sockid);
        stream_enqueue(mmt->destroyq, cur);
        errno = EAGAIN;
        return -1;
    }

    /* if nonblocking socket, return EINPROCESS */
    if (sk->opts & NON_BLOCK) {
        errno = EINPROCESS;
        return -1;
    } else {
        while(1) {
            if (!cur) {
                fprintf(stderr, 
                    "stream destroyed.\n");
                errno = ETIMEOUT;
            }
            if (cur->state > TCP_ESTABLISHED) {
                fprintf(stderr, 
                    "Socket id %d, weird state\n", sockid);
                /* TODO: how to handle this */
                errno = ENOSYS;
                return -1;
            }
            if (cur->state == TCP_ESTABLISHED) {
                break;
            }
            usleep(1000);
        }
    }

    return 0;
}


/* close stream close */
inline int 
close_stream_socket(int cpu_id, int sockid)
{
    mmutcpd_manager_t mmt = g_mmutcpd[cpu_id];
    socket_map_t      sk;
    tcp_stream_t      cur;
    int               ret;

    if (!mmt) {
        return -1;
    } 

    cur = mmt->socketq[sockid].stream;
    if (!cur) {
        fprintf(stderr, 
            "Socket id %d, does not exist\n", sockid);
        errno = ENOTCONN;
        return -1;
    }

    if (cur->closed) {
        fprintf(stderr, 
            "Socket id %d, already closed stream\n", sockid);
        return 0;
    }
    cur->closed = TRUE;

    cur->sk = NULL;
    
    if (cur->state == TCP_CLOSE) {
        stream_enqueue(mmt->destroyq, cur);
        mmt->wakeup_flag = TRUE;
        return 0;
    } else if (cur->state == TCP_SYN_SENT) {
        stream_enqueue(mmt->destroyq, cur);
        mmt->wakeup_flag = TRUE;
        return -1;
    } else if (cur->state != TCP_ESTABLISHED && 
        cur->state != TCP_CLOSE_WAIT) {
        fprintf(stderr, 
            "stream id %d at state %d\n", cur->id, cur->state);
        errno = EBADF;
        return -1;
    }

    cur->snd_var->on_closeq = TRUE;
    ret = stream_queue(mmt->closeq, cur);
    mmt->wakeup_flag = TRUE;
    if (ret < 0) {
        fprintf(stderr, 
            "Faield to enqueue the stream to close.\n");
        errno = EAGAIN;
        return -1;
    }

    return 0;
}


/* close listening socket */
inline int 
close_listening_socket(int cpu_id, int sockid)
{
    mmutcpd_manager_t mmt = g_mmutcpd[cpu_id];
    tcp_listener_t    listener;

    if (!mmt) {
        return -1;
    }

    listener = mmt->socketq[sockid].listener;
    if (!listener) {
        errno = EINVAL;
        return -1;
    }

    if (listener->acceptq) {
        destroy_stream_queue(mmt->acceptq);
        listener->acceptq = NULL;
    }

    pthread_mutex_lock(&listener->accept_lock);
    pthread_cond_signal(&listener->accept_cond);
    pthread_mutex_unlock(&listener->accept_lock);

    pthread_cond_destroy(&listener->accept_cond);
    pthread_mutex_destroy(&listener->accept_lock);

    free(listener);
    mmt->socketq[sockid].listener = NULL;

    return 0;
}