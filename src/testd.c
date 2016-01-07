
#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>

#include <sys/shm.h>
#include <sys/queue.h>

#include <mtcp_api.h>
#include <mtcp_epoll.h>

#include "cpu.h"
#include "http_parsing.h"
#include "debug.h"

#define MAX_FLOW_NUM  (1000)

#define RCVBUF_SIZE (8*1024)
#define SNDBUF_SIZE (2*1024)

#define MAX_EVENTS (MAX_FLOW_NUM * 3)

#define MAX_CPUS 16
#define MAX_FILES 30

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

#ifndef ERROR
#define ERROR (-1)
#endif

#define HT_SUPPORT FALSE

#define IP_RANGE 1
#define MAX_IP_STR_LEN 16

#define _DEBUG_

#define ERR_EXIT(m)    \
do {                   \
    perror(m);         \
    exit(EXIT_FAILURE);\
} while(0) 

#define CQ_LOCK(lock) do {                            \
    while (!__sync_bool_compare_and_swap(&lock, 0, 1)) \
        sched_yield();                                \
} while(0)

#define CQ_UNLOCK(lock) do { \
    *lock = 0;               \
} while(0)

const int core = 1;
const short s_port = 81;
char host[MAX_IP_STR_LEN+1] = "10.0.0.4";
static in_addr_t daddr;
static in_port_t dport;
static in_addr_t saddr;

int mtcp_manager_base = 1000, sh_mctx_id;;
int events_base       = 2000, sh_events_id;
int socket_base       = 3000, sh_sockets_id;

mctx_t mctx;

enum app_call_type {
    call_mtcp_getsockopt,
    call_mtcp_setsockopt,
    call_mtcp_setsock_nonblock,
    call_mtcp_socket_ioctl,
    call_mtcp_socket,
    call_mtcp_bind,
    call_mtcp_listen,
    call_mtcp_accept,
    call_mtcp_init_rss,
    call_mtcp_connect,
    call_mtcp_close,
    call_mtcp_abort,
    call_mtcp_read,
    call_mtcp_write,
    call_mtcp_epoll_create,
    call_mtcp_epoll_ctl,
    call_mtcp_epoll_wait
};

char *call_name[] = {
    "call_mtcp_getsockopt",
    "call_mtcp_setsockopt",
    "call_mtcp_setsock_nonblock",
    "call_mtcp_socket_ioctl",
    "call_mtcp_socket",
    "call_mtcp_bind",
    "call_mtcp_listen",
    "call_mtcp_accept",
    "call_mtcp_init_rss",
    "call_mtcp_connect",
    "call_mtcp_close",
    "call_mtcp_abort",
    "call_mtcp_read",
    "call_mtcp_write",
    "call_mtcp_epoll_create",
    "call_mtcp_epoll_ctl",
    "call_mtcp_epoll_wait"
};

typedef struct call_args {
    enum app_call_type call_type;
    int  lcore_id;//mctx mctx;
    int  sockid;
    int  level;
    int  optname;
    int   optval;
    socklen_t optlen;
    int  request;
    void *argp;
    int  domain;
    int  type;
    int  protocol;
    struct sockaddr addr;
    socklen_t addrlen;
    int  backlog;
    in_addr_t saddr_base;
    int  num_addr;
    in_addr_t daddr;  
    in_addr_t dport;  
    char buf[4096];
    int  len;
    int  size;
    int  epid;
    int  op;
    struct mtcp_epoll_event event;
    int  maxevents;
    int  timeout;
    int  lock;
    TAILQ_ENTRY(call_args) call_args_link;
} call_args;

struct event_args
{
    struct mtcp_epoll_event events[MAX_EVENTS];
    struct mtcp_epoll_event ev;
	int n;
};
struct event_args *eva;
int shm_event_args_id;

#ifndef _INDEX_TYPE_
#define _INDEX_TYPE_
typedef uint32_t index_type;
typedef int32_t signed_index_type;
#endif

struct call_queue 
{
    index_type _capacity;
    volatile index_type _head;
    volatile index_type _tail;

    struct call_args _q[30000]; 
};
typedef struct call_queue * call_queue_t;
call_queue_t cq;
int shm_call_queue_id;

struct call_args_pool
{
    call_args call_pool[30000];
    TAILQ_HEAD(call_args_head, call_args) call_args_list;
};
struct call_args_pool *cap;
int shm_call_args_pool_id;

void 
InitArgsPool(struct call_args_pool *cap)
{
    int i;
    TAILQ_INIT(&cap->call_args_list);
    for (i = 0; i < 30000; i++) {
        TAILQ_INSERT_TAIL(&cap->call_args_list, cap->call_pool + i, 
            call_args_link);
    }
}

void 
DestroyArgsPool(struct call_args_pool *cp)
{
    if (!cp) {
        return;
    }

    struct call_args *tmp;
    while (tmp = TAILQ_FIRST(&cp->call_args_list)) {
        TAILQ_REMOVE(&cp->call_args_list, tmp, call_args_link);
        tmp = NULL;
    }
    free (cp);
}

static inline index_type 
NextIndex(call_queue_t sq, index_type i)
{
    return (i != sq->_capacity ? i + 1: 0);
}

static inline index_type 
PrevIndex(call_queue_t sq, index_type i)
{
    return (i != 0 ? i - 1: sq->_capacity);
}

int 
CallQueueIsEmpty(call_queue_t sq)
{
    return (sq->_head == sq->_tail);
}

static inline void 
CallMemoryBarrier(struct call_args * volatile call, volatile index_type index)
{
    __asm__ volatile("" : : "m" (call), "m" (index));
}

void
InitCallQueue(call_queue_t sq, int capacity)
{
    sq->_capacity = capacity;
    sq->_head = sq->_tail = 0;
}

void 
DestroyCallQueue(call_queue_t sq)
{
    if (!sq)
        return;

    free(sq);
}

int 
CallEnqueue(call_queue_t sq, call_args *call)
{
    index_type h = sq->_head;
    index_type t = sq->_tail;
    index_type nt = NextIndex(sq, t);

    if (nt != h) {
        sq->_q[t] = *call;
        sq->_tail = nt;
        return 0;
    }

    TRACE_ERROR("Exceed capacity of call queue!\n");
    return -1;
}

struct call_args *
CallDequeue(call_queue_t sq)
{
    index_type h = sq->_head;
    index_type t = sq->_tail;

    if (h != t) {
        call_args *call = &sq->_q[h];
        sq->_head = NextIndex(sq, h);
        return call;
    }

    return NULL;
}

struct sync_area
{
	int lock[20];
	int vals[20][5];
	char buf[8192];
};
struct sync_area * sa;
int shm_sync_area_id;

void inline 
ProcessCall(call_args *call)
{
	int ret = 0;
	printf("call_name:%s\n", call_name[call->call_type]);
    switch (call->call_type) {
        case call_mtcp_getsockopt:
            ret = mtcp_getsockopt(mctx, call->sockid, call->level, call->optname, 
                &call->optval, &call->optlen);
			sa->vals[call_mtcp_getsockopt][0] = ret;
			sa->vals[call_mtcp_getsockopt][1] = call->optval;
            CQ_UNLOCK(&sa->lock[call_mtcp_getsockopt]);
            break;
        
        case call_mtcp_setsockopt:
            ret = mtcp_setsockopt(mctx, call->sockid, call->level, call->optname, 
                &call->optval, call->optlen);
			sa->vals[call_mtcp_setsockopt][0] = ret;
			CQ_UNLOCK(&sa->lock[call_mtcp_setsockopt]);
            break;
        
        case call_mtcp_setsock_nonblock:
            ret = mtcp_setsock_nonblock(mctx, call->sockid);
            sa->vals[call_mtcp_setsock_nonblock][0] = ret;
			CQ_UNLOCK(&sa->lock[call_mtcp_setsock_nonblock]);
			break;
        
        //case call_mtcp_socket_ioctl:
        case call_mtcp_socket:
            ret = mtcp_socket(mctx, call->domain, call->type, call->protocol);
			if (ret < 0) {
				ERR_EXIT("mtcp_socket");
			}
			if (call->type == SOCK_STREAM) {
				printf("SSSSSSSSSSSSSSSSSSSS\n");
			}
            sa->vals[call_mtcp_socket][0] = ret;
			CQ_UNLOCK(&sa->lock[call_mtcp_socket]);
			break;

        case call_mtcp_bind:
            ret = mtcp_bind(mctx, call->sockid, &call->addr, call->addrlen);
            sa->vals[call_mtcp_bind][0] = ret;
			CQ_UNLOCK(&sa->lock[call_mtcp_bind]);
			break;

        case call_mtcp_listen:
            ret = mtcp_listen(mctx, call->sockid, call->backlog);
			sa->vals[call_mtcp_listen][0] = ret;
			CQ_UNLOCK(&sa->lock[call_mtcp_listen]);
            break;

        case call_mtcp_accept:
            ret = mtcp_accept(mctx, call->sockid, &call->addr, &call->addrlen);
            sa->vals[call_mtcp_accept][0] = ret;
			CQ_UNLOCK(&sa->lock[call_mtcp_accept]);
			break;

        case call_mtcp_init_rss:
            ret = mtcp_init_rss(mctx, call->saddr_base, call->num_addr, 
                call->daddr, call->dport);
            sa->vals[call_mtcp_init_rss][0] = ret;
			CQ_UNLOCK(&sa->lock[call_mtcp_init_rss]);
			break;

        case call_mtcp_connect:
			ret = mtcp_connect(mctx, call->sockid, &call->addr, call->addrlen);
			if (ret < 0) {
				ERR_EXIT("mtcp_connect");
			}
			sa->vals[call_mtcp_connect][0] = ret;
			CQ_UNLOCK(&sa->lock[call_mtcp_connect]);
			break;

        case call_mtcp_close:
            ret = mtcp_close(mctx, call->sockid);
            sa->vals[call_mtcp_close][0] = ret;
			CQ_UNLOCK(&sa->lock[call_mtcp_close]);
			break;

        case call_mtcp_abort:
            ret = mtcp_abort(mctx, call->sockid);
            sa->vals[call_mtcp_abort][0] = ret;
			CQ_UNLOCK(&sa->lock[call_mtcp_abort]);
			break;

        case call_mtcp_read:
            ret = mtcp_read(mctx, call->sockid, call->buf, call->len);
            sa->vals[call_mtcp_read][0] = ret;
			memcpy(sa->buf, call->buf, call->len);
			CQ_UNLOCK(&sa->lock[call_mtcp_read]);
            break;

        case call_mtcp_write:
            ret = mtcp_write(mctx, call->sockid, call->buf, call->len);
            sa->vals[call_mtcp_write][0] = ret;
			CQ_UNLOCK(&sa->lock[call_mtcp_write]);
			break;
    
		case call_mtcp_epoll_create:
            ret = mtcp_epoll_create(mctx, call->size);
			if (ret < 0) {
				ERR_EXIT("mtcp_epoll_create");
			}
            sa->vals[call_mtcp_epoll_create][0] = ret;
			//printf("...\n");sleep(20);
			CQ_UNLOCK(&sa->lock[call_mtcp_epoll_create]);
			break;

        case call_mtcp_epoll_ctl:
            ret = mtcp_epoll_ctl(mctx, call->epid, call->op, call->sockid, 
                &call->event);
			sa->vals[call_mtcp_epoll_ctl][0] = ret;
			if (ret < 0) {
				ERR_EXIT("mtcp_epoll_ctl");
			}
			CQ_UNLOCK(&sa->lock[call_mtcp_epoll_ctl]);
            break;

        case call_mtcp_epoll_wait:
            ret = mtcp_epoll_wait(mctx, call->epid, eva->events, 
                call->maxevents, call->timeout);
			if (ret < 0) {
				ERR_EXIT("mtcp_epoll_wait");
			}
			sa->vals[call_mtcp_epoll_wait][0] = ret;
			CQ_UNLOCK(&sa->lock[call_mtcp_epoll_wait]);
            break;

        default:
			break;


    }

	
}
int done = FALSE;
int core_limit = 1;
void
SignalHandler(int signum)
{
	int i;
	printf("Signal Handler...\n");
	for (i = 0; i < core_limit; i++) {
		done = TRUE;
	}
}

int client()
{
	mctx_t mctx;
	int ep_id;
	struct mtcp_epoll_event *events;
	int listen_id;
	int sockid;
	int ret;
	struct mtcp_epoll_event ev;
	struct sockaddr_in addr;
	int c;	
	int i, j, n;
	int r_len;
	char r_buf[RCVBUF_SIZE];
	int s_len;
	char s_buf[SNDBUF_SIZE+2];
	
	int sendi = 0, sendmax = 200;
	int core_nums;

	printf("client start...\n");
	core_nums = GetNumCPUs();

    ret = mtcp_init("client.conf");
	if (ret) {
		printf("Failed to initialize mtcp.\n");
		exit(-1);
	} else {
		printf("mtcp initialized.\n");
	}

	mctx = mtcp_create_context(core);

	ep_id = mtcp_epoll_create(mctx, MAX_EVENTS);

	for (i = 0; i < SNDBUF_SIZE; i++)
		s_buf[i] = 'A' + i % 26;
	s_buf[i] = 0;

	sockid = mtcp_socket(mctx, AF_INET, SOCK_STREAM, 0);
	if (sockid < 0) {
		printf("Failed to create socker!\n");
		exit(-1);
	}

	ret = mtcp_setsock_nonblock(mctx, listen_id);
	if (ret < 0) {
		printf("Failed to set socket in nonblocking mode.\n");
		exit(-1);
	}

	daddr = inet_addr(host);
	dport = htons(s_port);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = daddr;
	addr.sin_port = dport;

	ret = mtcp_connect(mctx, sockid, 
			(struct sockaddr *)&addr, sizeof(struct sockaddr_in));
	if (ret < 0) {
		perror("Failed to bind to the listening socket!\n");
		mtcp_close(mctx, sockid);
		exit(-1);
	}

	events = (struct mtcp_epoll_event *)calloc(
			MAX_EVENTS, sizeof(struct mtcp_epoll_event));
	if (!events) {
		perror("Failed to create event struct.\n");
	}

	ev.events = MTCP_EPOLLOUT;
	ev.data.sockid = sockid;
	mtcp_epoll_ctl(mctx, ep_id, MTCP_EPOLL_CTL_ADD, sockid, &ev);

	while (sendi++ < sendmax) {
		printf("%d\n", sendi);
		n = mtcp_epoll_wait(mctx, ep_id, events, core, -1);
		for (i = 0; i < n; i++) {
			sockid = events[i].data.sockid;
			if (events[i].events & MTCP_EPOLLIN) {
				memset(r_buf, 0, RCVBUF_SIZE);
				r_len = mtcp_read(mctx, sockid, r_buf, RCVBUF_SIZE);
#ifdef _DEBUG_
				printf("lmhtq: read %dB\n", r_len);
				for (j = 0; j < r_len; j++) {
					printf("%c", r_buf[j]);
					if (j % 256 == 255) {
						printf("\n");
					}
				}
#endif
				ev.events = MTCP_EPOLLOUT;
				ev.data.sockid = sockid;
				mtcp_epoll_ctl(mctx, ep_id, MTCP_EPOLL_CTL_MOD, sockid, &ev);
				if (r_len == 0) {
					printf("lmhtq: read 0\n");
					mtcp_close(mctx, sockid);
				}
			} else if (events[i].events & MTCP_EPOLLOUT) {
				s_len = mtcp_write(mctx, sockid, s_buf, SNDBUF_SIZE);
#ifdef _DEBUG_
				printf("lmhtq: write %dB\n", s_len);
#endif
				ev.events = MTCP_EPOLLOUT;
				ev.data.sockid = sockid;
				mtcp_epoll_ctl(mctx, ep_id, MTCP_EPOLL_CTL_MOD, sockid, &ev);
			}
		}

	}
	mtcp_close(mctx, sockid);
}

int testd()
{
    int ep_id;
    struct mtcp_epoll_event *events;
    int listen_id;
    int sockid;
    int ret;
    struct mtcp_epoll_event ev;
    struct sockaddr_in saddr;
    int c;  
    int i, j, n;
    int r_len;
    char r_buf[RCVBUF_SIZE + 2];
    int s_len;
    char s_buf[SNDBUF_SIZE + 2];
    int err;

    struct call_args *tmp;

    printf("server init...\n");
    ret = mtcp_init("client.conf");
    if (ret) {
        printf("Failed to initialize mtcp.\n");
        exit(-1);
    }
	mtcp_register_signal(SIGINT, SignalHandler);
    
    mctx = mtcp_create_context(core);
    
    shm_call_args_pool_id = shmget((key_t)1234, 
        sizeof(struct call_args_pool), 0666|IPC_CREAT);
    if (shm_call_args_pool_id == -1) {
        ERR_EXIT("shm_call_args_pool_id get failed");
    }
    cap = (struct call_args_pool*)shmat(shm_call_args_pool_id, NULL, 0);
    if ((int)cap == -1) {
        ERR_EXIT("shm_call_args_pool_id shmat failed");
    }
    InitArgsPool(cap);

    shm_call_queue_id = shmget((key_t)1235, 
        sizeof(struct call_queue), 0666|IPC_CREAT);
    if (shm_call_queue_id == -1) {
        ERR_EXIT("shm_call_queue_id get failed");
    }
    cq = (call_queue_t)shmat(shm_call_queue_id, NULL, 0);
    if ((int)cq == -1) {
        ERR_EXIT("shm_call_queue_id shmat failed");
    }
    InitCallQueue(cq, 30000);

    shm_event_args_id = shmget((key_t)1236, 
        sizeof(struct event_args), 0666|IPC_CREAT);
    if (shm_event_args_id == -1) {
        ERR_EXIT("shm_event_args_id get failed");
    }
    eva = (struct event_args*)shmat(shm_event_args_id, NULL, 0);
    if ((int)eva == -1) {
        ERR_EXIT("shm_event_args_id shmat failed");
    }
	
	shm_sync_area_id = shmget((key_t)1237, 
			sizeof(struct sync_area), 0666|IPC_CREAT);
	if (shm_sync_area_id == -1) {
		ERR_EXIT("shm_sync_area_id get failed");
	}
	sa = (struct sync_area *)shmat(shm_sync_area_id, NULL, 0);
	if (sa == -1) {
		ERR_EXIT("shm_sync_area_id shmat failed");
	}
	
	done = FALSE;
    while (!done) {
		tmp = CallDequeue(cq);
        if (!tmp) {
			continue;
		}
		ProcessCall(tmp);
    }
	printf("destroy...\n");
	mtcp_destroy();
}

int main()
{
	//client();
    testd();
    return 0;
}

