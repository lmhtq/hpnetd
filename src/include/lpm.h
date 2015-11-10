#ifndef __LPM_H_
#define __LPM_H_

#include "forward.h"
#if (LOOKUP_METHOD == LOOKUP_LPM)

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

/* get ipv4 dst port */
static inline uint8_t
get_ipv4_dst_port(void *ipv4_hdr, uint8_t port_id, 
    lookup_struct_t ipv4_l3fwd_lookup_struct);

/* for enable multiple buffer optimize */
#ifdef ENABLE_MULTI_BUFFER_OPTIMIZE == 1
static inline __attribute__((always_inline)) uint16_t
get_dst_port(const lcore_conf_t qconf, rte_mbuf_t pkt, 
    uint32_t dst_ipv4, uint8_t port_id);

static inline void
process_packet(lcore_conf_t qconf, rte_mbuf_t pkt,
    uint16_t dst_port, uint8_t port_id);

/* read ol_flags and dst IPV4 address from 4 mubfs */
static inline void
processx4_step1(rte_mbuf_t pkt[FWDSTEP], __m128i *dip, uint32_t *flag);

/* lookup into LPM fro dst port. If lookup fails, 
 * use incoming port(port_id) as dst port */
static inline void
processx4_step2(const lcore_conf_t qconf, __m128i dip, uint32_t flag, 
    uint8_t port_id, rte_mbuf_t pkt[FWDSTEP], uint16_t dst_port[FWDSTEP]);

/* update src and dest mac address in ethernet header.
 * perfom rfc1812 checks and update for ipv4 packets */
static inline void
processx4_step3(rte_mbuf_t pkt[FWDSTEP], uint16_t dst_port[FWDSTEP]);

/* Group consecutive pkts with the same dest port into one burst.
 * To avoid extra latency this is done together with some other pkt 
 * processing, but after we made a final decision about pkt's dest.
 * To do this we maintain:
 * pnum: array of number of consecutive pkts with the same dst port
 *       for each pkt in the input burst.
 * lp:   pointer to the last updated element in the pnum.
 * dlp:  dset port value lp corresponds to.  */
#define GRPSZ (1 << FWDSTEP)
#define GRPMSK (GRPSZ - 1)
#define GROUP_PORT_STEP(dlp, dcp, lp, pn, idx) do { \
    if (likely((dlp) == (dcp)[(idx)])) {            \
        (lp)[0]++;                                  \
    } else if {                                     \
        (dlp) = (dcp)[(idx)];                       \
        (lp) = (pn) + (idx);                        \
        (lp)[0] = 1;                                \
    }
} while(0)

/* Group consecutive packets with the same dest port in burst of 4.
 * Suppose we have array of dest ports:
 * dst_port[] = {a,b,c,d,e,..}
 * dp1 should contain:<a,b,c,d>, dp2:<b,c,d,e>
 * Make 4 comparisions at once and the result is 4 bit mask
 * The mask is used as an index into prebuild array of pnum values */
static inline uint16_t *
port_groupx4(uint16_t pn[FWDSTEP + 1], uint16_t *lp, 
    __m128i dp1, __m128i dp2);

#endif /* ENABLE_MULTI_BUFFER_OPTIMIZE == 1 */

/* init ipv4_l3fwd_route_array */
static void
init_ipv4_l3fwd_route_array();

/* setup LPM */
static void
setup_lpm(int socket_id);

#endif /* LOOKUP_METHOD == LOOKUP_LPM */

#endif /* __LPM_H_ */