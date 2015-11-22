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

    ep->rw_queue = init_event_queue(size);
    if (!ep->rw_queue) {
        free_event_queue(ep->apps_queue);
        free_event_queue(ep->mmutcpd_queue);
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
    free_event_queue(ep->rw_queue);

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


/* add a epoll event */
inline int
add_epoll_event(mmutcpd_epoll_t ep, int queue_type, 
    socket_t sk, uint32_t event)
{
    event_queue_t eq;
    int ind;

    if (!ep || !sk || !event_type) {
        fprintf(stderr, "Invalid value ep or sk or event_type!"
            "%s:%s\n", __FILE__, __LINE__);
        return -1;
    }

    if (sk->event_type & event_type) {
        return 0;
    }

    if (queue_type == MMUTCPD_QUEUE) {
        eq = ep->mmutcpd_queue;
    } else if (queue_type == APP_QUEUE) {
        eq = ep->apps_queue;
        /* this between app and mmutcpd, other parts are well 
         * lock-free? */
        pthread_mutex_lock(&ep->epoll_lock);
    } else if (queue_type == RW_QUEUE) {
        eq = ep->rw_queue;
    } else {
        fprintf(stderr, "Invalid queue_type!"
            "%s:%s\n", __FILE__, __LINE__);
        return -1;
    }

    if (eq->num_events >= eq->size) {
        if (queue_type == APP_QUEUE) 
            pthread_mutex_unlock(&ep->epoll_lock);
        fprintf(stderr, "event_queue full!"
            "%s:%s\n", __FILE__, __LINE__);
        return -1;
    }
    
    eq->end++;
    if (eq->end >= eq->size)
        eq->end = 0;
    ind = eq->end;
    sk->events |= event;
    eq->events[ind].events = event;
    eq->events[ind].data = sk->ep_data;
    eq->events[ind].sockid = sk->id;

    eq->num_events++;
    if (queue_type == APP_QUEUE) 
        pthread_mutex_unlock(&ep->epoll_lock);

    return 0;
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
    if (sk->epoll & EPOLL_IN) {
        tcp_recv_vars_t rcv_var = stream->rcv_var;
        if (rcv_var->rcvbuf && rcv_var->rcvbuf->merged_len > 0) {
            /* add a read event */
            add_epoll_event(ep, RW_QUEUE, sk, EPOLL_IN);
        } else if (stream->state == TCP_CLOSE_WAIT) {
            /* add a close event */
            /* TODO: ?? why use two??? I one is enough! */
            add_epoll_event(ep, RW_QUEUE, sk, EPOLL_IN);
        }
    }

    /* generate write event */
    if (sk->epoll & EPOLL_OUT) {
        tcp_send_vars_t snd_var = stream->snd_var;
        if (!snd_var->sndbuf || 
            (snd_var->sndbuf && snd_var->sndbuf->len < snd_var->snd_wnd)) {
            /* TODO: mtcp maybe wrong here! */
            /* add a write event */
            if (sk->events & EPOLL_OUT) {
                add_epoll_event(ep, RW_QUEUE, sk, EPOLL_OUT);
            }
        }
    }
}


/* mmutcpd epoll control */
int mmutcpd_epoll_ctl(int cpu_id, int ep_id, int op, 
    int sockid, event_t event)
{
    mmutcpd_manager_t mmt = g_mmutcpd[cpu_id];
    mmutcpd_epoll_t   ep;
    socket_t          sk;
    uint32_t          events;

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

    if (!(event || op == EPOLL_CTRL_DEL)) {
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

        events = event->events;
        events |= (EPOLL_ERR | EPOLL_HUP);/* registered as default */
        sk->ep_data = event->data;
        sk->epoll = events;

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

        events = event->events;
        events |= (EPOLL_ERR | EPOLL_HUP);
        sk->ep_data = event->data;
        sk->epoll = events;

        /* TODO: other socktype:pipe */
        if (sk->socktype == SOCK_STREAM)
            generate_stream_events(mmt, ep, sk);

    } else if ( op == EPOLL_CTRL_DEL ) {
        if (!sk->sockid) {
            fprintf(stderr, "EPOLL_CTRL_DEL failed, origin sockid does not exsit."
                "%s:%s\n", __FILE__, __LINE__));
            return -1;
        }

        sk->epoll = EPOLL_NONE;

    }

}

/* mmutcpd_epoll_wait */
int 
mmutcpd_epoll_wait(int cpu_id, int ep_id, event_t events, 
    int max_events, int timeout)
{
    mmutcpd_manager_t mmt = g_mmutcpd[cpu_id];
    mmutcpd_epoll_t   ep;
    event_queue_t     eq;
    event_queue_t     eq_rw;
    socket_t          sk;
    
    int valid;
    int i, cnt, ret,
    int num_events;

    if (ep_id < 0 || ep_id >= m_config.max_concurrency) {
        fprintf(stderr, "ep_id out of range!\n"
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
    if (!ep || !events || max_events <= 0) {
        fprintf(stderr, "Invalid value of ep or (max_)events."
            "%s:%s\n", __FILE__, __LINE__));
        return -1;
    }

    if (pthread_mutex_lock(&ep->epoll_lock)) {
        fprintf(stderr, "epoll_lock already locked."
            "%s:%s\n", __FILE__, __LINE__));
        return -1;
    }

wait:
    eq = ep->apps_queue;
    eq_rw = eq->rw_queue;

    /* wait until event occurs */
    while (eq->num_events == 0 && eq_rw->num_events == 0 && timeout != 0) {
        ep->waiting = TRUE;

        if (unlikely(timeout > 0)) {
            struct timespec deadline;
            clock_gettime(CLOCK_REALTIME, &deadline);
            if (timeout > 1000) {
                deadline.tv_sec += timeout / 1000;
                timeout %= 1000;
            }
            deadline.tv_nsec += timeout * 1000000;
            if (deadline.tv_nsec >= 1000000000) {
                deadline.tv_sec++;
                deadline.tv_nsec -= 1000000000;
            }

            ret = pthread_cond_timewait(&ep->epoll_cond, 
                &ep->epoll_lock, &deadline);
            if (ret && ret != ETIMEOUT) {
                pthread_mutex_unlock(ep->epoll_lock);
                fprintf(stderr, "pthread_cond_timewait failed."
                    "%s:%s\n", __FILE__, __LINE__));
                return -1;
            }

            timeout = 0;
        } else {
            ret = pthread_cond_wait(&ep->epoll_cond, 
                &ep->epoll_lock);
            if (ret) {
                pthread_mutex_unlock(ep->epoll_lock);
                fprintf(stderr, "pthread_cond_wait failed."
                    "%s:%s\n", __FILE__, __LINE__));
                return -1;
            }

        }

        ep->waiting = FALSE;

        if (mmt->ctx->done || mmt->ctx->exit || mmt->ctx->interrupt) {
            mmt->ctx->interrupt = FALSE;
            pthread_mutex_unlock(&epoll_lock);
            fprintf(stderr, "invalid ctx->done or exit or interrupt."
                    "%s:%s\n", __FILE__, __LINE__));
            return -1;
        }
    }

    /* fetch event from apps_queue */
    fetch_epoll_events(mmt, eq, max_events);
    /* fetch event from rw_queue */
    fetch_epoll_events(mmt;, eq_rw, max_events);

    if (cnt == 0 && timeout != 0) {
        goto wait;
    }

    pthread_mutex_unlock(&ep->epoll_lock);

    return cnt;
}

/* fetch epoll event */
inline int 
fetch_epoll_events(mmutcpd_manager_t mmt, event_queue_t eq;
    int max_events)
{
    socket_t   sk;
    int num_events, cnt, i, valid;
    cnt = 0;
    num_events = eq->num_events;
    for (i = 0; i < num_events && cnt < max_events; i++) {
        sk = mmt->socketq[eq->events[eq->start].sockid];
        valid = TRUE;
        if (sk->socktype == SOCK_UNUSED)
            valid = FALSE;
        if (!(sk->epoll & eq->events[eq->start].events))
            valid = FALSE;
        if (!(sk->events & eq->events[eq->start].events))
            valid = FALSE;
        
        if (valid) {
            events[cnt++] = eq->events[eq->start];
        }

        sk->events &= (~eq->events[eq->start].events);
        eq->start++;
        eq->num_events--;
        if (eq->start >= eq->size) 
            eq->start = 0;
    }

}