#ifndef _EVENTPOLL_H_
#define _EVENTPOLL_H_

/* event type */
enum event_type
{
    EPOLL_NONE = 0x001,
    EPOLL_IN = 0x002,
    EPOLL_OUT = 0x004,
    EPOLL_ERR = 0x008
};

/* basic event struct: type and its id */
struct event
{
    uint32_t event_type;
    uint32_t sockid;
};
typedef struct event * event_t;

/* event queue */
struct event_queue
{
    event_t events; /* events array */
    int start;      /* left edge */
    int end;        /* right edge */
    int size;       /* the events array's size */
    int num_events; /* now the number of the num_events */
};
typedef struct event_queue * event_queue_t;

/* init event queue */
event_queue_t
init_event_queue(int size);

/* free event queue */
void
free_event_queue(event_queue_t eq);

/* TODO */
int
mmutcpd_epoll_create(int cpu_id, int size);

/* TODO */
int
mmutcpd_epoll_close(int cpu_id);

/* TODO */
int
raise_pending_stream_events(mmutcpd_manager_t mmt, )

#endif /* _EVENTPOLL_H_ */