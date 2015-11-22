#include "eventpoll.h"
#include "config.h"

/* init event queue */
event_queue_t
init_event_queue(int size)
{
    event_queue_t eq;

    eq = (event_queue_t)calloc(1, sizeof(struct event_queue));
    if (!eq) {
        fprintf(stderr, "Create event_queue node failed!" 
            "%s:%s\n", __FILE__, __LINE__));
        return NULL;
    }

    eq->start = eq->end = 0;
    eq->size = size;
    eq->events = (event_t)calloc(size, sizeof(struct event));
    if (!eq->events) {
        fprintf(stderr, "Create event_queue failed!" 
            "%s:%s\n", __FILE__, __LINE__));
        return NULL;    
    }
    eq->num_events = 0;

    return eq;
}


/* free event queue */
void
free_event_queue(event_queue_t eq)
{
    /* free events */
    if (eq->events) {
        free(eq->events);
    }

    /* free eq */
    free(eq);
}


/* mmutcpd epoll init 
 * after this, it can be used to create many sockets.
 * in other words, can use many mmutpcd_epoll_create*/
int 
mmutcpd_epoll_init(int cpu_id, int size)
{
    mmutcpd_manager_t mmt = g_mmutcpd[cpu_id];
    stream_queue_t    skq;
    mmutcpd_epoll_t   ep;

    if (size <= 0) {
        fprintf(stderr, "epoll create failed in size!\n", 
            "%s:%s\n", __FILE__, __LINE__));
        return -1;
    }

    skq = init_socket_queue(size);
    if (!skq) {
        fprintf(stderr, "socket_queue create failed!\n"
            "%s:%s\n", __FILE__, __LINE__));
        return -1;
    }
    mmt->socketq = skq;

    ep = (struct mmutcpd_epoll *)calloc(1, sizeof(struct mmutcpd_epoll));
    if (!ep) {
        fprintf(stderr, "epoll create failed!\n"
            "%s:%s\n", __FILE__, __LINE__));
        return -1;
    }

    /* create event queues */
    ep->apps_queue = init_event_queue(size);
    if (!ep->apps_queue)
        return -1;

    ep->mmutcpd_queue = init_event_queue(size);
    if (!ep->mmutcpd_queue) {
        free_event_queue(ep->apps_queue);
        return -1;
    }

    mmutcpd->ep = ep;

    if (pthread_mutex_init(&ep->epoll_lock, NULL)) {
        return -1;
    }
    if (pthread_cond_init(&ep->epoll_cond, NULL)) {
        return -1;
    }

}

/* mmutcpd epoll create one socket */
int 
mmutcpd_epoll_create(int cpu_id)
{
    mmutcpd_manager_t mmt = g_mmutcpd[mctx->cpu];
    mmutcpd_epoll_t   ep;
    socket_t          sk;

    ep = mmt->ep;

    sk = allocate_socket(cpu_id, SOCK_EPOLL, TRUE);
    if (!sk) {
        return NULL;
    }
    
    sk->ep = ep;

    return sk->id;
}


/* mmutcpd epoll close one socket */
void
mmutcpd_epoll_close(int cpu_id, int ep_id)
{
    /* close epoll socket */
    free_socket(cpu_id, ep_id);
}


/* mmutcpd epoll destroy 
 * pair use with mmutcpd epoll init */
void 
mmutcpd_epoll_destroy(int cpu_id)
{
    mmutcpd_manager_t mmt = g_mmutcpd[cpu_id];
    stream_queue_t    skq;
    mmutcpd_epoll_t   ep;

    ep = mmt->ep;
    if (!ep) {
        errno = EINVAL;
        return -1;
    }

    /* free event queues */
    free_event_queue(ep->apps_queue);
    free_event_queue(ep->mmutcpd_queue);

    /* destroy lock */
    pthread_mutex_lock(&ep->epoll_lock);
    pthread_cond_signal(&ep->epoll_cond);
    pthread_mutex_unlock(&ep->epoll_lock);

    pthread_cond_destroy(&ep->epoll_cond);
    pthread_cond_destroy(&ep->epoll_lock);
    free(ep);

    /* free socket queue */
    free_socket_queue(skq);
}


/* generate stream events */
inline int 
generate_stream_events(mmutcpd_manager_t mmt, 
    mmutcpd_epoll_t ep, socket_t sk)
{
    tcp_stream_t stream = sk->stream;

    if (!stream) {
        fprintf(stderr, "stream is NULL!"
            "%s:%s\n", __FILE__, __LINE__);
        return -1;
    }
    if (stream->state < TCP_ESTABLISHED) {
        fprintf(stderr, "stream has not established!"
            "%s:%s\n", __FILE__, __LINE__);
        return -1;
    }

    /* generate read events */
    if (sk->event_type & EPOLL_IN) {
        tcp_recv_vars_t rcv_var = stream->rcv_var;
        if (rcv_var->rcvbuf && rcv_var->rcvbuf->merged_len > 0) {
            /* add a read event */
            add_epoll_event(ep, USR_SHADOW_EVENT_QUEUE, sk, EPOLL_IN);
        } else if (stream->state == TCP_CLOSE_WAIT) {
            /* add a close event */
            /* TODO: ?? why use two??? I one is enough! */
            add_epoll_event(ep, USR_SHADOW_EVENT_QUEUE, sk, EPOLL_IN);
        }
    }

    /* generate write event */
    if (sk->event_type & EPOLL_OUT) {
        tcp_send_vars_t snd_var = stream->snd_var;
        if (!snd_var->sndbuf || 
            (snd_var->sndbuf && snd_var->sndbuf->len < snd_var->snd_wnd)) {
            /* TODO: mtcp maybe wrong here! */
            /* add a write event */
            add_epoll_event(ep, USR_SHADOW_EVENT_QUEUE, sk, EPOLL_OUT);
        }
    }
}


/* mmutcpd epoll control */
int mmutcpd_epoll_ctl(int cpu_id, int ep_id, int op, 
    int sockid, event_t ev)
{
    mmutcpd_manager_t mmt = g_mmutcpd[cpu_id];
    mmutcpd_epoll_t   ep;
    socket_t          sk;
    uint32_t          event_type;

    if (ep_id < 0 || ep_id >= m_config.max_concurrency) {
        fprintf(stderr, "ep_id out of range!\n"
            "%s:%s\n", __FILE__, __LINE__));
        return -1;
    }

    if (sockid < 0 || sockid >= m_config.max_concurrency) {
        fprintf(stderr, "sockid out of range!\n"
            "%s:%s\n", __FILE__, __LINE__));
        return -1;
    }

    if (mmt->socketq[ep_id].socktype != SOCK_EPOLL) {
        fprintf(stderr, "socket init failed before!"
            " socktype is not SOCK_EPOLL!\n"
            "%s:%s\n", __FILE__, __LINE__));
        return -1;
    }

    ep = mmt->socketq[ep_id].ep;
    if (!eq) {
        fprintf(stderr, "socket_queue init failed before!"
            " its ep is invalid!\n"
            "%s:%s\n", __FILE__, __LINE__));
        return -1;
    }

    if (!(ev || op == EPOLL_CTRL_DEL)) {
        fprintf(stderr, "Invalid value of ev or op."
            "%s:%s\n", __FILE__, __LINE__));
        return -1;
    } 

    sk = &mmt->socketq[ep_id];

    if (op == EPOLL_CTRL_ADD) {/* add a event */
        if (sk->sockid) {
            fprintf(stderr, "this socket's event sockid "
                "has been set!%s:%s\n", __FILE__, __LINE__));
            return -1;
        }

        event_type = ev->event_type;
        event_type |= (EPOLL_ERR | EPOLL_HUP);/* registered as default */
        sk->event_type = event_type;
        sk->sockid = ev->sockid;

        /* TODO: other socktype:pipe */
        if (sk->socktype == SOCK_STREAM)
            generate_stream_events(mmt, ep, sk);

    } else if (op == EPOLL_CTRL_MOD) {
        if (!sk->sockid) {
            /* ?? */
            pthread_mutex_unlock(&ep->epoll_lock);
            fprintf(stderr, "EPOLL_CTRL_MOD failed, origin sockid does not exsit."
                "%s:%s\n", __FILE__, __LINE__));
            return -1;
        }

        event_type = ev->event_type;
        event_type |= (EPOLL_ERR | EPOLL_HUP);
        sk->event_type = ev->event_type;
        sk->sockid = ev->sockid;

        /* TODO: other socktype:pipe */
        if (sk->socktype == SOCK_STREAM)
            generate_stream_events(mmt, ep, sk);

    } else if ( op == EPOLL_CTRL_DEL ) {
        if (!sk->sockid) {
            fprintf(stderr, "EPOLL_CTRL_DEL failed, origin sockid does not exsit."
                "%s:%s\n", __FILE__, __LINE__));
            return -1;
        }

        sk->event_type = EPOLL_NONE;

    }

}

/* TODO */
int 
raise_pending_stream_events(mmutcpd_manager_t mmutcpd, 
        struct EPoll *ep, socket_map_t socket)
{
    tcp_stream *stream = socket->stream;

    if (!stream)
        return -1;
    if (stream->state < TCP_ST_ESTABLISHED)
        return -1;

    /* if there are payloads already read before epoll registration */
    /* generate read event */
    if (socket->epoll & EPOLL_IN) {
        struct tcp_recv_vars *rcvvar = stream->rcvvar;
        if (rcvvar->rcvbuf && rcvvar->rcvbuf->merged_len > 0) {
            add_epoll_event(ep, USR_SHADOW_EVENT_QUEUE, socket, EPOLL_IN);
        } else if (stream->state == TCP_ST_CLOSE_WAIT) {
            add_epoll_event(ep, USR_SHADOW_EVENT_QUEUE, socket, EPOLL_IN);
        }
    }

    /* same thing to the write event */
    if (socket->epoll & EPOLL_OUT) {
        struct tcp_send_vars *sndvar = stream->sndvar;
        if (!sndvar->sndbuf || 
                (sndvar->sndbuf && sndvar->sndbuf->len < sndvar->snd_wnd)) {
            if (!(socket->events & EPOLL_OUT)) {
                add_epoll_event(ep, USR_SHADOW_EVENT_QUEUE, socket, EPOLL_OUT);
            }
        }
    }

    return 0;
}

/* TODO */
int 
EPoll_ctl(mctx_t mctx, int epid, 
        int op, int sockid, struct EPoll_event *event)
{
    mmutcpd_manager_t mmutcpd;
    struct EPoll *ep;
    socket_map_t socket;
    uint32_t events;

    mmutcpd = GetmmutcpdManager(mctx);
    if (!mmutcpd) {
        return -1;
    }

    if (epid < 0 || epid >= CONFIG.max_concurrency) {
        TRACE_API("Epoll id %d out of range.\n", epid);
        errno = EBADF;
        return -1;
    }

    if (sockid < 0 || sockid >= CONFIG.max_concurrency) {
        TRACE_API("Socket id %d out of range.\n", sockid);
        errno = EBADF;
        return -1;
    }

    if (mmutcpd->smap[epid].socktype == SOCK_UNUSED) {
        errno = EBADF;
        return -1;
    }

    if (mmutcpd->smap[epid].socktype != SOCK_EPOLL) {
        errno = EINVAL;
        return -1;
    }

    ep = mmutcpd->smap[epid].ep;
    if (!ep || (!event && op != EPOLL_CTL_DEL)) {
        errno = EINVAL;
        return -1;
    }
    socket = &mmutcpd->smap[sockid];

    if (op == EPOLL_CTL_ADD) {
        if (socket->epoll) {
            errno = EEXIST;
            return -1;
        }

        /* EPOLLERR and EPOLLHUP are registered as default */
        events = event->events;
        events |= (EPOLL_ERR | EPOLL_HUP);
        socket->ep_data = event->data;
        socket->epoll = events;

        if (socket->socktype == SOCK_STREAM) {
            raise_pending_stream_events(mmutcpd, ep, socket);
        } else if (socket->socktype == SOCK_PIPE) {
            RaisePendingPipeEvents(mctx, epid, sockid);
        }

    } else if (op == EPOLL_CTL_MOD) {
        if (!socket->epoll) {
            pthread_mutex_unlock(&ep->epoll_lock);
            errno = ENOENT;
            return -1;
        }

        events = event->events;
        events |= (EPOLL_ERR | EPOLL_HUP);
        socket->ep_data = event->data;
        socket->epoll = events;

        if (socket->socktype == SOCK_STREAM) {
            raise_pending_stream_events(mmutcpd, ep, socket);
        } else if (socket->socktype == SOCK_PIPE) {
            RaisePendingPipeEvents(mctx, epid, sockid);
        }

    } else if (op == EPOLL_CTL_DEL) {
        if (!socket->epoll) {
            errno = ENOENT;
            return -1;
        }

        socket->epoll = EPOLLNONE;
    }

    return 0;
}

/* TODO */
int 
EPoll_wait(mctx_t mctx, int epid, 
        struct EPoll_event *events, int maxevents, int timeout)
{
    mmutcpd_manager_t mmutcpd;
    struct EPoll *ep;
    struct event_queue *eq;
    struct event_queue *eq_shadow;
    socket_map_t event_socket;
    int validity;
    int i, cnt, ret;
    int num_events;

    mmutcpd = GetmmutcpdManager(mctx);
    if (!mmutcpd) {
        return -1;
    }

    if (epid < 0 || epid >= CONFIG.max_concurrency) {
        TRACE_API("Epoll id %d out of range.\n", epid);
        errno = EBADF;
        return -1;
    }

    if (mmutcpd->smap[epid].socktype == SOCK_UNUSED) {
        errno = EBADF;
        return -1;
    }

    if (mmutcpd->smap[epid].socktype != SOCK_EPOLL) {
        errno = EINVAL;
        return -1;
    }

    ep = mmutcpd->smap[epid].ep;
    if (!ep || !events || maxevents <= 0) {
        errno = EINVAL;
        return -1;
    }

    ep->stat.calls++;

#if SPIN_BEFORE_SLEEP
    int spin = 0;
    while (ep->num_events == 0 && spin < SPIN_THRESH) {
        spin++;
    }
#endif /* SPIN_BEFORE_SLEEP */

    if (pthread_mutex_lock(&ep->epoll_lock)) {
        if (errno == EDEADLK)
            perror("EPoll_wait: epoll_lock blocked\n");
        assert(0);
    }

wait:
    eq = ep->usr_queue;
    eq_shadow = ep->usr_shadow_queue;

    /* wait until event occurs */
    while (eq->num_events == 0 && eq_shadow->num_events == 0 && timeout != 0) {

#if INTR_SLEEPING_mmutcpd
        /* signal to mmutcpd thread if it is sleeping */
        if (mmutcpd->wakeup_flag && mmutcpd->is_sleeping) {
            pthread_kill(mmutcpd->ctx->thread, SIGUSR1);
        }
#endif
        ep->stat.waits++;
        ep->waiting = TRUE;
        if (timeout > 0) {
            struct timespec deadline;

            clock_gettime(CLOCK_REALTIME, &deadline);
            if (timeout > 1000) {
                int sec;
                sec = timeout / 1000;
                deadline.tv_sec += sec;
                timeout -= sec * 1000;
            }

            if (deadline.tv_nsec >= 1000000000) {
                deadline.tv_sec++;
                deadline.tv_nsec -= 1000000000;
            }

            //deadline.tv_sec = mmutcpd->cur_tv.tv_sec;
            //deadline.tv_nsec = (mmutcpd->cur_tv.tv_usec + timeout * 1000) * 1000;
            ret = pthread_cond_timedwait(&ep->epoll_cond, 
                    &ep->epoll_lock, &deadline);
            if (ret && ret != ETIMEDOUT) {
                /* errno set by pthread_cond_timedwait() */
                pthread_mutex_unlock(&ep->epoll_lock);
                TRACE_ERROR("pthread_cond_timedwait failed. ret: %d, error: %s\n", 
                        ret, strerror(errno));
                return -1;
            }
            timeout = 0;
        } else if (timeout < 0) {
            ret = pthread_cond_wait(&ep->epoll_cond, &ep->epoll_lock);
            if (ret) {
                /* errno set by pthread_cond_wait() */
                pthread_mutex_unlock(&ep->epoll_lock);
                TRACE_ERROR("pthread_cond_wait failed. ret: %d, error: %s\n", 
                        ret, strerror(errno));
                return -1;
            }
        }
        ep->waiting = FALSE;

        if (mmutcpd->ctx->done || mmutcpd->ctx->exit || mmutcpd->ctx->interrupt) {
            mmutcpd->ctx->interrupt = FALSE;
            //ret = pthread_cond_signal(&ep->epoll_cond);
            pthread_mutex_unlock(&ep->epoll_lock);
            errno = EINTR;
            return -1;
        }
    
    }
    
    /* fetch events from the user event queue */
    cnt = 0;
    num_events = eq->num_events;
    for (i = 0; i < num_events && cnt < maxevents; i++) {
        event_socket = &mmutcpd->smap[eq->events[eq->start].sockid];
        validity = TRUE;
        if (event_socket->socktype == SOCK_UNUSED)
            validity = FALSE;
        if (!(event_socket->epoll & eq->events[eq->start].ev.events))
            validity = FALSE;
        if (!(event_socket->events & eq->events[eq->start].ev.events))
            validity = FALSE;

        if (validity) {
            events[cnt++] = eq->events[eq->start].ev;
            assert(eq->events[eq->start].sockid >= 0);

            TRACE_EPOLL("Socket %d: Handled event. event: %s, "
                    "start: %u, end: %u, num: %u\n", 
                    event_socket->id, 
                    EventToString(eq->events[eq->start].ev.events), 
                    eq->start, eq->end, eq->num_events);
            ep->stat.handled++;
        } else {
            TRACE_EPOLL("Socket %d: event %s invalidated.\n", 
                    eq->events[eq->start].sockid, 
                    EventToString(eq->events[eq->start].ev.events));
            ep->stat.invalidated++;
        }
        event_socket->events &= (~eq->events[eq->start].ev.events);

        eq->start++;
        eq->num_events--;
        if (eq->start >= eq->size) {
            eq->start = 0;
        }
    }

    /* fetch eventes from user shadow event queue */
    eq = ep->usr_shadow_queue;
    num_events = eq->num_events;
    for (i = 0; i < num_events && cnt < maxevents; i++) {
        event_socket = &mmutcpd->smap[eq->events[eq->start].sockid];
        validity = TRUE;
        if (event_socket->socktype == SOCK_UNUSED)
            validity = FALSE;
        if (!(event_socket->epoll & eq->events[eq->start].ev.events))
            validity = FALSE;
        if (!(event_socket->events & eq->events[eq->start].ev.events))
            validity = FALSE;

        if (validity) {
            events[cnt++] = eq->events[eq->start].ev;
            assert(eq->events[eq->start].sockid >= 0);

            TRACE_EPOLL("Socket %d: Handled event. event: %s, "
                    "start: %u, end: %u, num: %u\n", 
                    event_socket->id, 
                    EventToString(eq->events[eq->start].ev.events), 
                    eq->start, eq->end, eq->num_events);
            ep->stat.handled++;
        } else {
            TRACE_EPOLL("Socket %d: event %s invalidated.\n", 
                    eq->events[eq->start].sockid, 
                    EventToString(eq->events[eq->start].ev.events));
            ep->stat.invalidated++;
        }
        event_socket->events &= (~eq->events[eq->start].ev.events);

        eq->start++;
        eq->num_events--;
        if (eq->start >= eq->size) {
            eq->start = 0;
        }
    }

    if (cnt == 0 && timeout != 0)
        goto wait;

    pthread_mutex_unlock(&ep->epoll_lock);

    return cnt;
}

/* TODO */
inline int 
add_epoll_event(struct EPoll *ep, 
        int queue_type, socket_map_t socket, uint32_t event)
{
    struct event_queue *eq;
    int index;

    if (!ep || !socket || !event)
        return -1;
    
    ep->stat.issued++;

    if (socket->events & event) {
        return 0;
    }

    if (queue_type == mmutcpd_EVENT_QUEUE) {
        eq = ep->mmutcpd_queue;
    } else if (queue_type == USR_EVENT_QUEUE) {
        eq = ep->usr_queue;
        pthread_mutex_lock(&ep->epoll_lock);
    } else if (queue_type == USR_SHADOW_EVENT_QUEUE) {
        eq = ep->usr_shadow_queue;
    } else {
        TRACE_ERROR("Non-existing event queue type!\n");
        return -1;
    }

    if (eq->num_events >= eq->size) {
        TRACE_ERROR("Exceeded epoll event queue! num_events: %d, size: %d\n", 
                eq->num_events, eq->size);
        if (queue_type == USR_EVENT_QUEUE)
            pthread_mutex_unlock(&ep->epoll_lock);
        return -1;
    }

    index = eq->end++;

    socket->events |= event;
    eq->events[index].sockid = socket->id;
    eq->events[index].ev.events = event;
    eq->events[index].ev.data = socket->ep_data;

    if (eq->end >= eq->size) {
        eq->end = 0;
    }
    eq->num_events++;

#if 0
    TRACE_EPOLL("Socket %d New event: %s, start: %u, end: %u, num: %u\n",
            ep->events[index].sockid, 
            EventToString(ep->events[index].ev.events), 
            ep->start, ep->end, ep->num_events);
#endif

    if (queue_type == USR_EVENT_QUEUE)
        pthread_mutex_unlock(&ep->epoll_lock);

    ep->stat.registered++;

    return 0;
}