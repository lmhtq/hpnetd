#include "eventepoll.h"

/* init event queue */
event_queue_t
init_event_queue(int size)
{
    event_queue_t eq;

    eq = (event_queue_t)calloc(1, sizeof(struct event_queue));
    if (!eq) {
        fprintf(stderr, "Create event_queue node failed! 
            %s:%s\n", __FILE__, __LINE__));
        return NULL;
    }

    eq->start = eq->end = 0;
    eq->size = size;
    eq->events = (event_t)calloc(size, sizeof(struct event));
    if (!eq->events) {
        fprintf(stderr, "Create event_queue failed! 
            %s:%s\n", __FILE__, __LINE__));
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

/* TODO */
int 
mmutcpd_epoll_create(mctx_t mctx, int size)
{
    mmutcpd_manager_t mmutcpd = g_mmutcpd[mctx->cpu];
    struct mmutcpd_epoll *ep;
    socket_map_t epsocket;

    if (size <= 0) {
        errno = EINVAL;
        return -1;
    }

    ep = (struct mmutcpd_epoll *)calloc(1, sizeof(struct mmutcpd_epoll));
    if (!ep) {
        free_socket(mctx, epsocket->id, FALSE);
        return -1;
    }

    /* create event queues */
    ep->usr_queue = init_event_queue(size);
    if (!ep->usr_queue)
        return -1;

    ep->usr_shadow_queue = init_event_queue(size);
    if (!ep->usr_shadow_queue) {
        free_event_queue(ep->usr_queue);
        return -1;
    }

    ep->mmutcpd_queue = init_event_queue(size);
    if (!ep->mmutcpd_queue) {
        free_event_queue(ep->usr_queue);
        free_event_queue(ep->usr_shadow_queue);
        return -1;
    }

    mmutcpd->ep = ep;
    epsocket->ep = ep;

    if (pthread_mutex_init(&ep->epoll_lock, NULL)) {
        return -1;
    }
    if (pthread_cond_init(&ep->epoll_cond, NULL)) {
        return -1;
    }

    return epsocket->id;
}


/* TODO */
int 
EPoll_close(mctx_t mctx, int epid)
{
    mmutcpd_manager_t mmutcpd;
    struct EPoll *ep;

    mmutcpd = GetmmutcpdManager(mctx);
    if (!mmutcpd) {
        return -1;
    }

    ep = mmutcpd->smap[epid].ep;
    if (!ep) {
        errno = EINVAL;
        return -1;
    }

    free_event_queue(ep->usr_queue);
    free_event_queue(ep->usr_shadow_queue);
    free_event_queue(ep->mmutcpd_queue);
    free(ep);

    pthread_mutex_lock(&ep->epoll_lock);
    mmutcpd->ep = NULL;
    mmutcpd->smap[epid].ep = NULL;
    pthread_cond_signal(&ep->epoll_cond);
    pthread_mutex_unlock(&ep->epoll_lock);

    pthread_cond_destroy(&ep->epoll_cond);
    pthread_mutex_destroy(&ep->epoll_lock);

    return 0;
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