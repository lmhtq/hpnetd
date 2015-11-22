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
    sk.sockid = 0;
    sk.event_type = 0;

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