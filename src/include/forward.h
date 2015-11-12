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

#include <rte_lpm.h>
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

#include "memstruct.h"


/* send burst of pkts on an output interface */
inline int
send_burst(lcore_conf_t qconf, uint16_t n, uint8_t port);

/* enqueue a single pkt, add send burst if queue is filled */
inline int
send_single_packet(struct rte_mbuf *m, uint8_t port);

/* send packetsx4 */
inline __attribute__((always_inline)) void
send_packetsx4(lcore_conf_t qconf, uint8_t port,
    rte_mbuf_t m[], uint32_t num);

/* check whether the pkt is valid */
#define DO_RFC_1812_CHECKS
#ifdef DO_RFC_1812_CHECKS
inline int
is_valid_ipv4_pkt(struct ipv4_hdr *pkt, uint32_t link_len);
#endif /* DO_RFC_1812_CHECKS */

/* l3fwd simple forward */
inline void
l3fwd_simple_forward(struct rte_mbuf_t m, uint8_t port_id, 
    lcore_conf_t qconf) __attribute__((unused));

/* get the number of rx queues on specific port */
uint8_t 
get_port_n_rx_queues(const uint8_t port_id);

/* init the lcore_params */
int
init_lcore_params(int nb_port, int nb_queue, int nb_cpus);

/* init lcore rx queues, lcore_conf(_array) */
int
init_lcore_rx_queue(void);

/* init mem */
int
init_mem(unsigned nb_mbuf);

/* check lcore params */
int
check_lcore_params(void);

/* check port config */
int 
check_port_config(const unsigned nb_port);

/* check the link status of all ports in up to 9s, 
 *and print them finally */
void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask);

/* print mac address */
void
print_ethaddr(const char *name, const struct ether_addr *eth_addr);

/* config dpdk */
int 
config_dpdk();

/* main_loop */
int
main_loop(__attribute__((unused)) void *dummy);

/* init_dpdk */
int
init_dpdk();

#endif /* __FORWARD_H_ */
