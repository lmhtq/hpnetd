#ifndef __HASH_H_
#define __HASH_H_

#include "forward.h"
#if (LOOKUP_METHOD == LOOKUP_EXACT_MATCH)

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

#include "forward.h"

#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
#include <rte_hash_crc.h>
#define DEFAULT_HASH_FUN rte_hash_crc
#else
#include <rte_jhash.h>
#define DEFAULT_HASH_FUN rte_jhash
#endif


/* struct of ipv4_5tuple */
struct ipv4_5tuple
{
    uint32_t ip_dst;
    uint32_t ip_src;
    uint16_t port_dst;
    uint16_t port_src;
    uint8_t proto;
} __attribute__((__packed__)); 
typedef ipv4_5tuple * ipv4_5tuple_t;

/* union of ipv4_5tuple_host, struct ipv4_5tuple in host format */
union ipv4_5tuple_host
{
    struct
    {
        uint8_t pad0;
        uint8_t proto;
        uint16_t pad1;
        uint32_t ip_src;
        uint32_t ip_dst;
        uint16_t port_src;
        uint16_t port_dst;
    };
    __m128i xmm;/* SSE 128bit int */
};
typedef ipv4_5tuple_host * ipv4_5tuple_host_t;

/* struct of ipv4_l3fwd_route */
struct ipv4_l3fwd_route
{
    struct ipv4_5tuple key;
    uint8_t if_out;
};

/* maximum number of l3fwd_route table */
#define IPV4_L3FWD_NUM_ROUTES 1024
static ipv4_l3fwd_num_routes = 0;
/* route table */
static struct ipv4_l3fwd_route ipv4_l3fwd_route_array[IPV4_L3FWD_NUM_ROUTES];

/* lookup structure */
typedef struct rte_hash *lookup_struct_t;
typedef struct rte_hash * rte_hash_t;
static lookup_struct_t ipv4_l3fwd_lookup_struct[NB_SOCKETS];

#ifdef RTE_ARCH_x86_64
/* default to 4 million hash entries (approx) */
#define L3FWD_HASH_ENTRIES 1024*1024*4
#else
/* 32bit has less address-space for hugepage memory, limit to 1M entries */
#define L3FWD_HASH_ENTRIES 1024*1024*1
#endif

/* default number of hash entries */
#define HASH_ENTRY_NUMBER_DEFAULT 4
static uint32_t hash_entry_number = HASH_ENTRY_NUMBER_DEFAULT;

/* ipv4 L3 fwd result */
static uint8_t ipv4_l3fwd_out_if[L3FWD_HASH_ENTRIES] __rte_cache_aligned;

/* ipv4 hash crc */
static inline uint32_t
ipv4_hash_crc(const void *data, __rte_unused uint32_t data_len,
    uint32_t init_val);

/* three __m128i masks */
static __m128i mask0;
static __m128i mask1; /* no use, for ipv6*/
static __m128i mask2; /* no use, for ipv6*/

/* get ipv4 dest port */
static inline uint8_t
get_ipv4_dst_port(void *ipv4_hdr, uint8_t port_id, 
    lookup_struct_t ipv4_l3fwd_lookup_struct);

#if (ENABLE_MULTI_BUFFER_OPTIMIZE == 1)
#define MASK_ALL_PKTS 0xf
#define EXECLUDE_1ST_PKT 0xe
#define EXECLUDE_2ND_PKT 0xd
#define EXECLUDE_3RD_PKT 0xb
#define EXECLUDE_4TH_PKT 0x7

/* simple ipv4  fwd 4pkts */
static inline void
simple_ipv4_fwd_4pkts(struct rte_mbuf_t m[4], uint8_t port_id,
    lcore_conf_t qconf);

/* some typedef */
typedef struct ipv4_hdr * ipv4_hdr_t;
typedef struct ether_hdr * ether_hdr_t;
typedef unsigned char uchar;

#endif /* ENABLE_MULTI_BUFFER_OPTIMIZE == 1 */

/* simple ipv4 fwd 1 pkt */
static inline __attribute__((always_inline)) void
l3fwd_simple_forward(rte_mbuf_t m, uint8_t port_id, lcore_conf_t qconf);

/* process rfc1812 */
#ifdef DO_RFC_1812_CHECKS
#define IPV4_MIN_VER_IHL 0x45
#define IPV4_MAX_VER_IHL 0x4f
#define IPV4_MAX_VER_IHL_DIFF (IPV4_MAX_VER_IHL - IPV4_MIN_VER_IHL)
/* minimum value of IPV4 total length (20B) in network order */
#define IPV4_MIN_LEN_BE (sizeof(struct ipv4_hdr) << 8)
/* 
 *      the cons of rfc1812
 * - IP version number must be 4
 * - IP header length field must be >= 20B(5 words)
 * - IP total length field must be >= IP header length field
 * if it is a invalid pkt, set dest port to BAD_PORT
 */
static inline __attribute__((always_inline)) void
rfc1812_process(ipv4_hdr_t ipv4_hdr, uint16_t *dp, uint32_t flags);
#else
#define rfc1812_process(mb, dp) do{} while(0)
#endif /* DO_RFC_1812_CHECKS */

/* convert ipv4 tuple into host format */
static void convert_ipv4_5tuple(ipv4_5tuple_t key1, 
    ipv4_5tuple_host_t, key2);


/* init ipv4_l3fwd_route_array */
static int
init_ipv4_l3fwd_route_array(void);

#define BYTE_VALUE_MAX 256
#define ALL_32_BITS 0xffffffff
#define BIT_8_TO_15 0x0000ff00

/* populate ipv4 few flow into table */
static inline void
populate_ipv4_few_flow_into_table(const rte_hash_t h);

/* populate ipv4 many flow into table */
#define NUMBER_PORT_USED 4
static inline void
populate_ipv4_many_flow_into_table(const rte_hash_t h, 
    unsigned int nr_flow);

/* setup hash method for lookup */
static void
setup_hash(int socket_id);

#endif /* LOOKUP_METHOD == LOOKUP_EXACT_MATCH */

#endif /* __HASH_H_ */
