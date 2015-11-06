#ifndef __FORWARD_H_
#define __FORWARD_H_

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

/* forward method */
/* look up method */
#define LOOKUP_EXACT_MATCH 0
#define LOOKUP_LPM 1
#ifndef LOOKUP_METHOD
#define LOOKUP_METHOD LOOKUP_LPM
#endif

/* 
 * When set to 0, simple forwrding path is enabled
 * When set to 1, optimized forwarding is enabled.(use sse4.1)
 */
#if ((LOOKUP_METHOD == LOOKUP_LPM) && !define(__SSE4_1__))
#define ENABLE_MULTI_BUFFER_OPTIMIZE 0
#else
#define ENABLE_MULTI_BUFFER_OPTIMIZE 1
#endif

#if (LOOKUP_METHOD == LOOKUP_EXACT_MATCH)
#include <rte_hash.h>
#include "hash.h"
#elif (LOOKUP_METHOD == LOOKUP_LPM)
#include <rte_lpm.h>
#include <lpm.h>
#else
#error("LOOKUP_METHOD set to wrong value")
#endif

#if (LOOKUP_METHOD == LOOKUP_EXACT_MATCH)
#include "hash.h"
#elif (LOOKUP_METHOD == LOOKUP_LPM)
#include "lpm.h"
#endif


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
static uint16_t bc_txd = RTE_TEST_TX_DESC_DEFAULT;

/* nic mac of ports */
static struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];
static __m128i val_eth[RTE_MAX_ETHPORTS];

/* replace the first 12Bytes of the ether header */
#define MASK_ETH 0x3f

/* mask of enabled ports */
static uint32_t enabled_port_mask = 0;

/**< port set in promiscuous mode off by default */
static int promiscuous = 0;

/**< NUMA is enabled by default  */
static int numa_on = 1;

/* struct of m_buf table */
typedef struct rte_mbuf *rte_mbuf_t;
struct mbuf_table
{
    uint16_t   len;
    rte_mbuf_t m_table[MAX_PKT_BURST]
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
static struct lcore_params lcore_params_array[MAX_LCORE_PARAMS]

/* it is a pointer, same as lcore_params_array */
static struct lcore_params * lcore_params = lcore_params_array;

/* number of lcore_params */
static uint16_t nb_lcore_params;

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
            .rss_hf = ETH_RSS_IP,
        }
    },
    .txmode = {
        .mp_mode = ETH_MQ_TX_NONE,
    }
};

/* pktmbuf pool */
typedef struct rte_mempool *rte_mempool_t;
static rte_mempool_t pktmbuf_pool[NB_SOCKETS];

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

/* send burst of pkts on an output interface */
static inline int
send_burst(struct lcore_conf_t qconf, uint16_t n, uint8_t port);

/* enqueue a single pkt, add send burst if queue is filled */
static inline int
send_single_packet(struct rte_mbuf *m, uint8_t port);

/* send packetsx4 */
static inline __attribute__((always_inline)) void
send_packetsx4(struct lcore_conf_t qconf, uint8_t port,
    rte_mbuf_t m[], uint32_t num);

/* check whether the pkt is valid */
#define DO_RFC_1812_CHECKS
#ifdef DO_RFC_1812_CHECKS
static inline int
is_valid_ipv4_pkt(struct ipv4_hdr *pkt, uint32_t link_len);
#endif /* DO_RFC_1812_CHECKS */

/* l3fwd simple forward */
static inline void
l3fwd_simple_forward(struct rte_mbuf_t m, uint8_t port_id, 
    lcore_conf_t qconf) __attribute__((unused));

/* init the lcore_params */
static int
init_lcore_params(int nb_port, int nb_queu, int nb_cpus);

/* init lcore rx queues, lcore_conf(_array) */
static int
init_lcore_rx_queue(void);

/* init mem */
static int
init_mem(unsigned nb_mbuf);

/* main_loop */
static int
main_loop(__attribute__((unused)) void *dummy);

#endif
