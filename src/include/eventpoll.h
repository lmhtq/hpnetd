#ifndef _EVENTPOLL_H_
#define _EVENTPOLL_H_

/* epoll operations */
enum epoll_op
{
    EPOLL_CTRL_ADD = 1,
    EPOLL_CTRL_DEL,
    EPOLL_CTRL_MOD,
};

/* event type */
enum event_type
{
    EPOLL_NONE = 0x000,
    EPOLL_IN = 0x001,
    EPOLL_OUT = 0x002,
    EPOLL_ERR = 0x004,
    EPOLL_HUP = 0x008,
    EPOLL_ET = (1 << 32)
};

/* event_queue type */
enum event_queue_type
{
    APP_QUEUE = 0,
    MMUTCPD_QUEUE,
    RW_QUEUE
};

/* epoll data */
typedef union epoll_data
{
    void     *ptr;
    int      sockid;
    uint32_t u32;
    uint64_t u64;
} epoll_data_t;

/* basic event struct: type and its id */
struct event
{
    uint32_t     events;
    epoll_data_t data;
    int          sockid;
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

/* mmutcpd epoll
 * This is a mmutcpd-level struct.
 * It maintains such things: apps' events, this cpu's mmutcpd' events */
struct mmutcpd_epoll
{
    /* apps' events queue, mainly related to socket */
    event_queue_t apps_queue;
    /* internal events queue */
    event_queue_t mmutcpd_queue;
    /* r/w event queue, mainly related to tcp */
    event_queue_t rw_queue;

    uint8_t waiting;
    pthread_cond_t  epoll_cond;
    pthread_mutex_t epoll_lock;
};
typedef struct mmutcpd_epoll * mmutcpd_epoll_t;

/* init event queue */
event_queue_t
init_event_queue(int size);

/* free event queue */
void
free_event_queue(event_queue_t eq);

/* mmutcpd epoll init 
 * after this, it can be used to create many sockets.
 * in other words, can use many mmutpcd_epoll_create*/
int 
mmutcpd_epoll_init(int cpu_id int size);

/* mmutcpd epoll create one socket */
int
mmutcpd_epoll_create(int cpu_id);

/* mmutcpd epool close one socket */
void
mmutcpd_epoll_close(int cpu_id, int ep_id);

/* mmutcpd epoll destroy 
 * pair use with mmutcpd epoll init */
int 
mmutcpd_epoll_destroy(int cpu_id);

/* mmutcpd epoll control */
int mmutcpd_epoll_ctl(int cpu_id, int ep_id, int op, 
    int sockid, event_t ev);

/* generate stream event */
inline int 
generate_stream_events(mmutcpd_manager_t mmt, 
    mmutcpd_epoll_t ep, socket_t sk);

/* add a epoll event */
inline int
add_epoll_event(mmutcpd_epoll_t ep, int queue_type, 
    socket_t sk, uint32_t event_type);

/* mmutcpd_epoll_wait */
int 
mmutcpd_epoll_wait(int cpu_id, int ep_id, event_t events, 
    int max_events, int timeout);

/* fetch epoll event */
inline int 
fetch_epoll_events(mmutcpd_manager_t mmt, event_queue_t eq;
    int max_events);

#endif /* _EVENTPOLL_H_ */