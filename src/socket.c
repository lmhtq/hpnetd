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
    sk->id = skq->end;
    sk->socktype = socktype;
    sk->opts = 0;
    sk->valid = 1;
    sk->epoll = 0;
    sk->events = 0;
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
    sk->saddr = *addr_in;
    sk->opts |= ADDR_BIND;

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
        sk->socktype = SOCK_LISTENER;
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

    sk->listener = listener;
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

    listener = sk->listener;

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


/* close socket */
int 
mmutcpd_close(int cpu_id, int sockid)
{
    mmutcpd_manager_t mmt = g_mmutcpd[cpu_id];
    socket_map_t      sk;
    int               ret;

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

    switch (sk->socktype) {
        case SOCK_STREAM:
            ret = close_stream_socket(cpu_id, sockid);
            break;
        
        case SOCK_LISTENER:
            ret = close_listening_socket(cpu_id, sockid);
            break;
        
        case SOCK_EPOLL:
            ret = mmutcpd_epoll_close(cpu_id, sockid);
            break;
        
        /* TODO PIPE*/
       
        default:
            errno = EINVAL;
            ret = 1;
            break;
    }

    free_socket(cpu_id, sockid, FALSE);

    return ret;
}


/* abort socket */
int 
mmutcpd_abort(int cpu_id, int sockid)
{
    mmutcpd_manager_t mmt = g_mmutcpd[cpu_id];
    socket_map_t      sk;
    tcp_stream_t      cur;
    int               ret;

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

    cur = sk->stream;
    if (!cur) {
        fprintf(stderr, 
            "Socket id %d, stream does not exist.\n", sockid);
        errno = ENOTCONN;
        return -1;
    }

    free_socket(cpu_id, socket_id, FALSE);
    cur->sk = NULL;

    if (cur->state == TCP_CLOSE) {
        fprintf(stderr, 
            "Socket id %d, stream connection already reset\n", sockid);
        return ERROR;
    } else if (cur->state == TCP_SYN_SENT) {
        /* TODO: this should notify event failure to all previous
         * read() or write() calls  */
        cur->state = TCP_CLOSE;
        cur->close_reason = TCP_ACTIVE_CLOSE;
        stream_queue(mmt->destroyq)
        mmt->wakeup_flag = TRUE;
        return 0;
    } else if (cur->state == TCP_CLOSING ||
        cur->state == TCP_LAST_ACK ||
        cur->state == TCP_TIME_WAIT) {
        cur->state = TCP_CLOSE;
        cur->close_reason = TCP_ACTIVE_CLOSE;
        stream_enqueue(mmt->destroyq);
        mmt->wakeup_flag = TRUE;
        return 0;
    }

    /* the stream strcuture will be destroyed after sending RST */
    if (cur->snd_var->on_resetq) {
        fprintf(stderr, 
            "Socket id %d, stream call mmutcpd_abort "
            "when in reset queue", sockid);
        errno = ECONNRESET;
        return -1;
    }

    cur->snd_var->on_resetq = TRUE;
    ret = stream_queue(mmt->resetq, cur);
    mmt->wakeup_flag = TRUE;

    if (ret < 0) {
        fprintf(stderr, 
            "Failed to enqueue the stream to clsoe\n");
        errno = EAGAIN;
        return -1;
    }

    return 0;
}


/* copy data to app */
inline int 
cp_to_app(int cpu_id, tcp_stream_t cur, char *buf, int len)
{
    tcp_recv_vars_t rcv_var = cur->rcv_var;
    uint32_t        pre_rcv_wnd;
    int             copy_len;

    copy_len = min(rcv_var->rcvbuf->merged_len, len);
    if (copy_len <= 0) {
        errno = EAGAIN;
        return -1;
    }

    pre_rcv_wnd = rcv_var->rcv_wnd;
    /* copy data to app buffer and remove it from receiving buffer */
    memcpy(buf, rcv_var->rcvbuf, copy_len);
    /* TODO: rb_remove, AT_APP, rcv_buf */
    rb_remove(mmt->rbm_rcv, rcv_var->rcv_var, copy_len, AT_APP);
    rcv_var->rcv_wnd = rcv_var->rcvbuf->size - 1 - rcv_var->rcvbuf->last_len;

    /* advertise newly feed receive buffer */
    if (cur->need_wnd_adv) {
        if (rcv_var->rcv_wnd > cur->snd_var->eff_mss) {
            if (!cur->snd_var->on_ackq) {
                cur->snd_var->on_ackq = TRUE;
                stream_enqueue(mmt->ackq, cur);
                cur->need_wnd_adv = FALSE;
                mmt->wakeup_flag = TRUE;
            }
        }
    }

    /* UNUSED(pre_rcv_end) */
    return copy_len;
}

/* read socket */
int 
mmutcpd_read(int cpu_id, int sockid, char *buf, int len)
{
    mmutcpd_manager_t mmt = g_mmutcpd[cpu_id];
    socket_map_t      sk;
    tcp_stream_t      cur;
    tcp_recv_vars_t   rv;
    int               event_remaining;
    int               ret;

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

    /* TODO: PIPE */

    if (sk->socktype != SOCK_STREAM) {
        fprintf(stderr, 
            "Socket id %d is not a stream socket\n", sockid);
        errno = ENOTSCOK;
        return -1;
    }

    /* stream's state should be ESTABLISHED, FIN_WAIT_1, 
     * FIN_WAIT_2, CLOSE_WAIT */
    cur = sk->stream;
    /* TODO: change the state list, becasue the value related to it */
    if (!cur || !(cur->state >= TCP_ESTABLISHED && 
        cur->state <= TCP_CLOSE_WAIT)) {
        errno = ENOTCONN;
        return -1;
    }

    rv = cur->rcv_var;
    pthread_spin_lock(&rv->read_lock);
    ret = cp_to_app(cpu_id, cur, buf, len);

    event_remaining = FALSE;
    /* if there are remaining payload, generate EPOLL_IN,
     * may because the user buffer is insufficient */
    if (sk->epoll & EPOLL_IN) {
        if (!(sk->epoll & EPOLL_ET) && rv->rcvbuf->merged_len > 0) {
            event_remaining = TRUE;
        }
    }

    /* if waiting for close, notify it if no remaing data */
    if (cur->state == TCP_CLOSE_WAIT && 
        rv->rcvbuf->merged_len == 0 && ret > 0) {
        event_remaining = TRUE;
    }

    pthread_spin_unlock(&rv->read_lock);

    if (event_remaining) {
        if (sk->epoll) {
            add_epoll_event(mmt->ep, USR_SHADOW_EVENT_QUEUE, 
                sk, EPOLL_IN);
        }
    }

    return ret;
}


/* readv socket */
int 
mmutcpd_readv(int cpu_id, int sockid, struct iovec *iov, int iov_num)
{
    mmutcpd_manager_t mmt = g_mmutcpd[cpu_id];
    socket_map_t      sk;
    tcp_stream_t      cur;
    tcp_recv_vars_t   rv;
    int               event_remaining;
    int               ret, bytes_read, i;

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

    /* TODO: PIPE */

    if (sk->socktype != SOCK_STREAM) {
        fprintf(stderr, 
            "Socket id %d is not a stream socket\n", sockid);
        errno = ENOTSCOK;
        return -1;
    }

    /* stream's state should be ESTABLISHED, FIN_WAIT_1, 
     * FIN_WAIT_2, CLOSE_WAIT */
    cur = sk->stream;
    /* TODO: change the state list, becasue the value related to it */
    if (!cur || !(cur->state >= TCP_CLOSE_WAIT && 
        cur->state <= TCP_CLOSE_WAIT)) {
        errno = ENOTCONN;
        return -1;
    }

    rv = cur->rcv_var;

    /* if CLOSE_WAIT and there is no payload, return 0 */
    if (cur->state == TCP_CLOSE_WAIT) {
        if (!rv->rcvbuf || rv->rcvbuf->merged_len == 0) {
            return 0;
        }
    }

    /* return EAGAIN if no receive buffer */
    if (sk->opts & NON_BLOCK) {
        if (!rv->rcvbuf || rv->rcvbuf->merged_len == 0) {
            errno = EAGAIN;
            return -1;
        }
    }

    pthread_spin_lock(&rv->read_lock);

    /* read and store the data to the vectored buffer */
    bytes_read = 0;
    for (i = 0; i < iov_num; i++) {
        if (iov[i].iov_len <= 0) {
            continue;
        }

        ret = cp_to_app(cpu_id, cur, iov[i].iov_base, iov[i].iov_len);
        if (ret <= 0) {
            break;
        } 

        bytes_read += ret;
        if (ret < iov[i].iov_len) {
            break;
        }
    }


    event_remaining = FALSE;
    /* if there are remaining payload, generate EPOLL_IN,
     * may because the user buffer is insufficient */
    if (sk->epoll & EPOLL_IN) {
        if (!(sk->epoll & EPOLL_ET) && rv->rcvbuf->merged_len > 0) {
            event_remaining = TRUE;
        }
    }

    /* if waiting for close, notify it if no remaing data */
    if (cur->state == TCP_CLOSE_WAIT && 
        rv->rcvbuf->merged_len == 0 && ret > 0) {
        event_remaining = TRUE;
    }

    pthread_spin_unlock(&rv->read_lock);

    if (event_remaining) {
        if (sk->epoll) {
            add_epoll_event(mmt->ep, USR_SHADOW_EVENT_QUEUE, 
                sk, EPOLL_IN);
        }
    }

    return ret;   
}

/* copy data from app */
inline int 
cp_from_app(int cpu_id, tcp_stream_t cur, char *buf, int len)
{
    tcp_send_vars_t sv = cur->snd_var;
    int             sndlen;
    int             ret;

    sndlen = min((int)sv->snd_wnd, len);
    if (sndlen <= 0) {
        errno = EAGAIN;
        return -1;
    }

    /* allocate send buffer is not exist */
    if (!sv->sndbuf) {
        /* TODO: sb_init() */
        sv->sndbuf = sb_init(mmt->rbm_snd, sv->iss + 1);
        if (!sv->sndbuf) {
            cur->close_reason = TCP_NO_MEM;
            errno = ENOMEM;
            return -1;
        }
    }

    /* TODO: sb_put() */
    ret = sb_put(mmt->rbm_snd, sv->sndbuf, buf, sndlen);
    assert(ret == sndlen);
    sv->snd_wnd = sv->sndbuf->size - sv->sndbuf->len;
    if (ret <= 0) {
        fprintf(stderr, 
            "sb_put failed. reason: %d (sndlen:%d, len:%d)\n", 
            ret, sndlen, (int)sv->sndbuf->len);
        errno = EAGAIN;
        return -1;
    }

    if (sv->snd_wnd <= 0) {
        fprintf(stderr, 
            "%u sending buffer became full! snd_wnd:%d\n", 
            cur->id, sv->snd_wnd);

    }

    return ret;
}

/* write socket */
int 
mmutcpd_write(int cpu_id, int sockid, char *buf, int len)
{
    mmutcpd_manager_t mmt = g_mmutcpd[cpu_id];
    socket_map_t      sk;
    tcp_stream_t      cur;
    tcp_send_vars_t   sv;
    int               ret;

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

    /* TODO: PIPE */

    if (sk->socktype != SOCK_STREAM) {
        fprintf(stderr, 
            "Socket id %d is not a stream socket\n", sockid);
        errno = ENOTSCOK;
        return -1;
    }

    /* stream's state should be ESTABLISHED, CLOSE_WAIT */
    cur = sk->stream;
    /* TODO: change the state list, becasue the value related to it */
    if (!cur || !(cur->state == TCP_ESTABLISHED || 
        cur->state == TCP_CLOSE_WAIT)) {
        errno = ENOTCONN;
        return -1;
    }

    if (len <= 0) {
        if (sk->socktype & NON_BLOCK) {
            errno = EAGAIN;
            return -1;
        } else {
            return 0;
        }
    }

    sv = cur->snd_var;

    ret = cp_from_app(cpu_id, cur, buf, len);

    if (ret > 0 && !(sv->on_sendq || sv->on_send_list)) {
        sv->on_sendq = TRUE;
        stream_enqueue(mmt->sendq, cur);
        mmt->wakeup_flag = TRUE;
    }

    if (ret == 0 && sk->socktype & NON_BLOCK) {
        errno = EAGAIN;
        return -1;
    }

    /* if there is remaing sending buffer, generate write event */
    if (sv->snd_wnd > 0) {
        if ( (sk->epoll & EPOLL_OUT) && 
            !(sk->epoll & EPOLL_ET)) {
            add_epoll_event(mmt->ep, USR_SHADOW_EVENT_QUEUE, 
                sk, EPOLL_OUT);
        }
    }

    return ret;
}

/* writev socket */
int 
mmutcpd_writev(int cpu_id, int sockid, struct iovec *iov, int iov_num)
{
    mmutcpd_manager_t mmt = g_mmutcpd[cpu_id];
    socket_map_t      sk;
    tcp_stream_t      cur;
    tcp_send_vars_t   sv;
    int               ret, to_write, i;

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

    /* TODO: PIPE */

    if (sk->socktype != SOCK_STREAM) {
        fprintf(stderr, 
            "Socket id %d is not a stream socket\n", sockid);
        errno = ENOTSCOK;
        return -1;
    }

    /* stream's state should be ESTABLISHED, CLOSE_WAIT */
    cur = sk->stream;
    /* TODO: change the state list, becasue the value related to it */
    if (!cur || !(cur->state == TCP_ESTABLISHED || 
        cur->state == TCP_CLOSE_WAIT)) {
        errno = ENOTCONN;
        return -1;
    }

    if (len <= 0) {
        if (sk->socktype & NON_BLOCK) {
            errno = EAGAIN;
            return -1;
        } else {
            return 0;
        }
    }

    sv = cur->snd_var;

    /* write from the vectored buffer */
    to_write  = 0;
    for (i = 0; i < iov_num; ++i)
    {
        if (iov[i].iov_len <= 0) {
            continue;
        }

        ret = cp_from_app(cpu_id, cur, iov[i].iov_base, iov[i].iov_len);
        if (ret <= 0) {
            break;
        }

        to_write += ret;

        if (ret <= iov[i].iov_len) {
            break;
        }

    }


    if (to_write > 0 && !(sv->on_sendq || sv->on_send_list)) {
        sv->on_sendq = TRUE;
        stream_enqueue(mmt->sendq, cur);
        mmt->wakeup_flag = TRUE;
    }

    if (to_write == 0 && (sk->socktype & NON_BLOCK)) {
        errno = EAGAIN;
        return -1;
    }

    /* if there is remaing sending buffer, generate write event */
    if (sv->snd_wnd > 0) {
        if ( (sk->epoll & EPOLL_OUT) && 
            !(sk->epoll & EPOLL_ET)) {
            add_epoll_event(mmt->ep, USR_SHADOW_EVENT_QUEUE, 
                sk, EPOLL_OUT);
        }
    }

    return to_write;
}

