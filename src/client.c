
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

#include "libtest.h"
#include "sys/shm.h"

#define HT_SUPPORT FALSE

#define IP_RANGE 1
#define MAX_IP_STR_LEN 16

#define _DEBUG_

const int core = 1;
const short s_port = 81;
char host[MAX_IP_STR_LEN+1] = "10.0.0.4";
static in_addr_t daddr;
static in_port_t dport;
static in_addr_t saddr;

int client()
{
	int mctx = 1;
	int ep_id;
	int listen_id;
	int sockid;
	int ret;
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

	ShareMemoryMap();
	
	printf("mapped\n");
	ep_id = mtcp_epoll_create(core, MAX_EVENTS);
	printf("epoll_created, ep_id:%d\n", ep_id);
	sleep(1);

	for (i = 0; i < SNDBUF_SIZE; i++)
		s_buf[i] = 'A' + i % 26;
	s_buf[i] = 0;

	sockid = mtcp_socket(core, AF_INET, SOCK_STREAM, 0);
	if (sockid < 0) {
		printf("Failed to create socker!\n");
		exit(-1);
	}
	printf("mtcp socket, sockid:%d\n", sockid);

	daddr = inet_addr(host);
	dport = htons(s_port);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = daddr;
	addr.sin_port = dport;

	ret = mtcp_connect(core, sockid, 
			(struct sockaddr *)&addr, sizeof(struct sockaddr_in));
	if (ret < 0) {
		ERR_EXIT("mtcp_connect");
		mtcp_close(mctx, sockid);
		exit(-1);
	}
	printf("mtcp_connect\n");

	eva->ev.events = MTCP_EPOLLOUT;
	eva->ev.data.sockid = sockid;
	mtcp_epoll_ctl(core, ep_id, MTCP_EPOLL_CTL_ADD, sockid, &eva->ev);
	printf("epoll_ctl\n");
	while (sendi++ < sendmax) {
		printf("%d\n", sendi);
		n = mtcp_epoll_wait(core, ep_id, eva->events, core, -1);
		printf("epoll_wait, n=%d\n", n);
		for (i = 0; i < n; i++) {
			sockid = eva->events[i].data.sockid;
			if (eva->events[i].events & MTCP_EPOLLIN) {
				memset(r_buf, 0, RCVBUF_SIZE);
				r_len = mtcp_read(core, sockid, r_buf, RCVBUF_SIZE);
#ifdef _DEBUG_
				printf("lmhtq: read %dB\n", r_len);
				for (j = 0; j < r_len; j++) {
					printf("%c", r_buf[j]);
					if (j % 256 == 255) {
						printf("\n");
					}
				}
#endif
				eva->ev.events = MTCP_EPOLLOUT;
				eva->ev.data.sockid = sockid;
				mtcp_epoll_ctl(core, ep_id, MTCP_EPOLL_CTL_MOD, sockid, &eva->ev);
				if (r_len == 0) {
					printf("lmhtq: read 0\n");
					mtcp_close(core, sockid);
				}
			} else if (eva->events[i].events & MTCP_EPOLLOUT) {
				s_len = mtcp_write(core, sockid, s_buf, SNDBUF_SIZE);
#ifdef _DEBUG_
				printf("lmhtq: write %dB\n", s_len);
#endif
				eva->ev.events = MTCP_EPOLLOUT;
				eva->ev.data.sockid = sockid;
				mtcp_epoll_ctl(core, ep_id, MTCP_EPOLL_CTL_MOD, sockid, &eva->ev);
			}
		}

	}
	mtcp_close(core, sockid);
}

int main()
{
	client();
	return 0;
}

