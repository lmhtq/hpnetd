#ifndef __MEMSTRUCT_H_
#define __MEMSTRUCT_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <inttypes.h>
#include <string.h>
#include <sys/queue.h>
#include <errno.h>
#include <stdarg.h>
#include <getopt.h>

#include <rte_common.h>
#include <rte_vect.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_string_fns.h>

#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_eal.h>

#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>

#include <rte_prefetch.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>

/* DPDK data structures */
/* the size of jambo pkt */
#define MAX_JAMBO_PKT_LEN 9600

/* how many buffer in a mempool to cache */
#define MEMPOOL_CACHE_SIZE 256

/* the size of buffer in mempool */
#define MBUF_SIZE (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)

/*set maximum number of mbuf */
#define NB_MBUF RTE_MAX(                                      \
    (nb_ports*nb_rx_queue*RTE_TEST_RX_DESC_DEFAULT +          \
    nb_ports*nb_lcores*MAX_PKT_BURST +                        \
    nb_ports*nb_tx_queue*RTE_TEST_RX_DESC_DEFAULT +           \
    nb_lcores*MEMPOOL_CACHE_SIZE),                            \
    (unsigned)8192 )

/* pkts to send in batch */
#define MAX_PKT_BURST 32

/* send all pkts if the queue has at least MAX_TX_BURST pkts */
#define MAX_TX_BURST (MAX_PKT_BURST / 2)

/* TX drain every ~100us */
#define BURST_TX_DRAIN_US 100 

/* number of socket */
#define NB_SOCKETS 8 

/* how many packets ahead to prefetch when reading pkts */
#define PREFETCH_OFFSET 3

/* invalid port */
#define BAD_PORT ((uint16_t)-1)

/* TODO: fill this comment */
#define FWDSTEP 4

/* number of RX/TX ring descriptors */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* nic mac of ports */
static struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];
static __m128i val_eth[RTE_MAX_ETHPORTS];

/* replace the first 12Bytes of the ether header */
#define MASK_ETH 0x3f

/* mask of enabled ports */
static uint32_t enabled_port_mask = 0;

/**< port set in promiscuous mode off by default */
static int promiscuous_on = 0;

/**< NUMA is enabled by default  */
static int numa_on = 1;

/* struct of m_buf table */
typedef struct rte_mbuf *rte_mbuf_t;
struct mbuf_table
{
    uint16_t   len;
    rte_mbuf_t m_table[MAX_PKT_BURST];
};

/* struct of lcore_rx_queue */
struct lcore_rx_queue
{
    uint8_t port_id;
    uint8_t queue_id;
} __rte_cache_aligned;

/*struct of lcore_parameters */
struct lcore_params
{
    uint8_t port_id;
    uint8_t queue_id;
    uint8_t lcore_id;
} __rte_cache_aligned;
typedef struct lcore_params *lcore_params_t;

/* maximum number of receive queues per lcore */
#define MAX_RX_QUEUE_PER_LCORE 16

/* maximum number of tx queue per port */
#define MAX_TX_QUEUE_PER_PORT RTE_MAX_ETHPORTS

/* maximum number of rx queue per port */
#define MAX_RX_QUEUE_PER_PORT 128

/* maximum size of lcore params array */
#define MAX_LCORE_PARAMS 1024
static struct lcore_params lcore_params_array[MAX_LCORE_PARAMS];

/* it is a pointer, same as lcore_params_array */
static struct lcore_params * lcore_params = lcore_params_array;

/* number of lcore_params */
static uint16_t nb_lcore_params = 0;

/* config of nic port */
static struct rte_eth_conf port_conf = {
    .rxmode = {
        /* multi-queue pkt distribution mode to be used. eg RSS */
        .mq_mode = ETH_MQ_RX_RSS, 
        /* only used if jumbo_frame is enabled */
        .max_rx_pkt_len = ETHER_MAX_LEN,
        /* hdr buf size (header_split enabled) */
        .split_hdr_size = 0,
        /**< header split disabled */
        .header_split = 0,
        /**< IP checksum offload enabled */
        .hw_ip_checksum = 1,
        /**< VLAN filtering disabled */
        .hw_vlan_filter = 0,
        /**< jumbo frame support disabled */
        .jumbo_frame = 0,
        /**< CRC stripped by hardware */
        .hw_strip_crc = 0,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf = ETH_RSS_TCP,
        }
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    }
};

/* rx_conf */
static struct rte_eth_rxconf rx_conf = {
    .rx_thresh = {
        .pthresh = 8,  /* RX prefetch threshold reg */
        .hthresh = 8,  /* RX host threshold reg */
        .wthresh = 4,  /* RX write-back threshold reg */
    },
    .rx_free_thresh = 32,
}; 

/* tx_conf */
static struct rte_eth_txconf tx_conf = {
    .tx_thresh = {
        .pthresh = 36,  /* TX prefetch threshold reg */
        .hthresh = 0,   /* TX host threshold reg */
        .wthresh = 0,   /* TX write-back threshold reg */
    },
    .tx_free_thresh = 0, /* PMD default */
    .tx_rs_thresh   = 0, /* PMD default */
    .txq_flags      = 0.
};

/* pktmbuf pool */
typedef struct rte_mempool *rte_mempool_t;
static rte_mempool_t pktmbuf_pool[NB_SOCKETS];

/* struct of ipv4_l3fwd_route */
struct ipv4_l3fwd_route {
    uint32_t ip;
    uint8_t depth;
    uint8_t if_out;
};

/* maximum number of l3fwd_route table */
#define IPV4_L3FWD_NUM_ROUTES 1024
static uint16_t ipv4_l3fwd_num_routes = 0;
/* route table */
static struct ipv4_l3fwd_route ipv4_l3fwd_route_array[IPV4_L3FWD_NUM_ROUTES];

/* maximum number of rules */
#define IPV4_L3FWD_LPM_MAX_RULES 1024
typedef struct rte_lpm *lookup_struct_t;
static lookup_struct_t ipv4_l3fwd_lookup_struct[NB_SOCKETS];

/* some typedef */
typedef struct ipv4_hdr * ipv4_hdr_t;
typedef struct ether_hdr * ether_hdr_t;
typedef unsigned char uchar;


/* config of lcore */
struct lcore_conf
{
    uint16_t              n_rx_queue;
    struct lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_PORT];
    uint16_t              tx_queue_id[RTE_MAX_ETHPORTS];
    struct mbuf_table     tx_mbufs[RTE_MAX_ETHPORTS];
    lookup_struct_t       ipv4_lookup_struct;
} __rte_cache_aligned;
typedef struct lcore_conf *lcore_conf_t;

/* config of per lcore */
static struct lcore_conf lcore_conf_array[RTE_MAX_LCORE];

/* it is a pointer, same as lcore_conf_array */
static lcore_conf_t lcore_conf = lcore_conf_array;

#endif /* __MEMSTRUCT_H_ */
