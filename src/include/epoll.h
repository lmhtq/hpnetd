#ifndef __EPOLL_H_
#define __EPOLL_H_

enum epoll_op
{
    EPOLL_CTRL_ADD = 1,
    EPOLL_CTRL_DEL = 2,
    EPOLL_CTRL_MOD = 3
};

enum event_type
{
    EPOLL_NONE = 0x000,
    EPOLL_IN = 0x001,
    EPOLL_PRI = 0x002,
    EPOLL_OUT = 0x004,
    EPOLL_RDNORM = 0x040,
    EPOLL_RDBAND = 0x080,
    EPOLL_WRNORM = 0x100,
    EPOLL_WRBAND = 0x200,
    EPOLL_MSG = 0x400,
    EPOLL_ERR = 0x008,
    EPOLL_HUP = 0x010,
    EPOLL_RDHUP = 0x2000,
    EPOLL_ONESHOT = (1<<30),
    EPOLL_ET = (1<<32),

};

typedef union epoll_data
{
    void     *ptr;
    int      sockid;
    uint32_t u32;
    uint64_t u64;
} epoll_data_t;

struct epoll_event
{
    uint32_t events;
    epoll_data_t data;
};

#endif /* __EPOLL_H_ */