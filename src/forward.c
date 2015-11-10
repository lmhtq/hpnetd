#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include "forward.h"
#include "config.h"

/* functions implements */


/* send burst of pkts on an output interface */
static inline int
send_burst(struct lcore_conf_t qconf, uint16_t n, uint8_t port)
{
    rte_mbuf_t *m_table;
    int ret;
    uint16_t queue_id;

    queue_id = qconf->tx_queue_id[port];
    m_table = (rte_mbuf_t *)qconf->tx_mbufs[port].m_table;

    ret = rte_eth_tx_burst(port, queue_id, m_table, n);
    if (unlikely(ret < n)) {
        do {
            rte_pktmbuf_free(m_table[ret])
        } while(++ret < n);
    }

    return 0;
}


/* enqueue a single pkt, add send burst if queue is filled */
static inline int
send_single_packet(struct rte_mbuf *m, uint8_t port)
{
    uint32_t lcore_id;
    uint16_t len;
    lcore_conf_t *qconf;

    lcore_id = rte_lcore_id();

    qconf = &lcore_conf[lcore_id];
    len = qconf->tx_mbufs[port].len;
    qconf->tx_mbufs[port].m_table[len] = m;
    len++;

    /* enough pkts to be send. >= MAX_PKT_BURST */
    if (unlikely(len == MAX_PKT_BURST)) {
        send_burst(qconf, MAX_PKT_BURST, port);
    }

    qconf->tx_mbufs[port].len = len;
    return 0;
}

/* send packetsx4 */
static inline __attribute__((always_inline)) void
send_packetsx4(struct lcore_conf_t qconf, uint8_t port,
    rte_mbuf_t m[], uint32_t num)
{
    uint32_t len, j, n;

    len = qconf->tx_mbufs[port].len;

    /* if TX buffer for that queue is empty, 
     * and we have enough pkts. then send them staightway. 
     */
    if (num >= MAX_TX_BURST && len == 0) {
        n = rte_eth_tx_burst(port, qconf->tx_queue_id[port], 
            m, num);
        if (unlikely(n < num)) {
            do {
                rte_pktmbuf_free(m[n]);
            } while (++n < num);
        }

        return;
    }

    /* put pkts into TX buffer for that queue */
    n = len + num;
    /* n is the number of pkts that can enqueue the queue */
    n = (n > MAX_PKT_BURST) ? MAX_PKT_BURST - len : num;

    /* Deff's device, for optimizing */
    j = 0;
    switch (n % FWDSTEP) {
    while (j < n) {
    case 0:
        qconf->tx_mbufs[port].m_table[len + j] = m[j];
        j++;
    case 3:
        qconf->tx_mbufs[port].m_table[len + j] = m[j];
        j++;
    case 2:
        qconf->tx_mbufs[port].m_table[len + j] = m[j];
        j++;
    case 1:
        qconf->tx_mbufs[port].m_table[len + j] = m[j];
        j++;
    } /* end of while */
    } /* end of switch */

    len += n;

    /* enough pkts to be sent */
    if (unlikely(len == MAX_PKT_BURST)) {
        send_burst(qconf, MAX_PKT_BURST, port);

        /* copy rest of the pkts into the TX buffer */
        len = num - n;
        j = 0;
        switch (n % FWDSTEP) {
        while (j < n) {
        case 0:
            qconf->tx_mbufs[port].m_table[j] = m[n + j];
            j++;
        case 3:
            qconf->tx_mbufs[port].m_table[j] = m[n + j];
            j++;
        case 2:
            qconf->tx_mbufs[port].m_table[j] = m[n + j];
            j++;
        case 1:
            qconf->tx_mbufs[port].m_table[j] = m[n + j];
            j++;
        } /* end of while */
        } /* end of switch */
    }

    qconf->tx_mbufs[port].len = len;

}

#ifdef DO_RFC_1812_CHECKS
/* check whether the pkt is valid */
static inline int
is_valid_ipv4_pkt(struct ipv4_hdr *pkt, uint32_t link_len)
{
    /* 1. the packet length must be large enough to 
     *    hold the minimum length legal IP datagram(20B) 
     */
    if (link_len < sizeof(struct ipv4_hdr))
        return -1;

    /* 2. IP checksum must be correct */
    /*    this is done by NIC */

    /* 3. IP version number must be 4 */
    if ( ( (pkt->version_ihl) >> 4 ) != 4 )
        return -3;

    /* 4. IP header length field must be large enough to
     *    hold minimum length legal IP datagram(20B = 5 words) 
     */
    if ( (pkt->version_ihl & 0xf) < 5 )
        return -4;

    /* 5.IP total length field must be large enough to 
     *   hold the IP datagram header, whose length is specified
     *   in the IP header length field.
     */
    if (rte_cpu_to_be_16(pkt->total_length) < sizeof(struct ipv4_hdr))
        return -5;
}
#endif /* DO_RFC_1812_CHECKS */


/* init the lcore_params */
static int
init_lcore_params(int nb_port, int nb_queue, int nb_cpus);
{
    int i, j, k;
    nb_lcore_params = 0;

    for (i = 0; i < nb_port; ++i) {
        for (j = 0; j < nb_queue; ++j) {
            for (k = 0; k < nb_cpu; k++) {
                lcore_params[nb_lcore_params][0] = i;/* port_id  */
                lcore_params[nb_lcore_params][1] = j;/* queue_id */
                lcore_params[nb_lcore_params][2] = k;/* lcore_id */
                nb_lcore_params++;
            }
        }
    }

    return 0;
}


/* get the number of rx queues on specific port */
static uint8_t 
get_port_n_rx_queues(const uint8_t port_id)
{
    int      queue = -1;
    uint16_t i;

    for (i = 0; i < nb_lcore_params; i++) {
        if (lcore_params[i].port_id == port_id && 
            lcore_params[i].queue_id > queue) {
            queue = lcore_params[i].queue_id;
        }
    }
    return (uint8_t)(++queue);
}

/* init lcore rx queues, lcore_conf(_array) */
static int
init_lcore_rx_queue(void)
{
    uint16_t i, nb_rx_queue;
    uint8_t  lcore;

    for (i = 0; i < nb_lcore_params; ++i) {
        lcore = lcore_params[i].lcore_id;
        nb_rx_queue = lcore_conf[lcore].n_rx_queue;
        if (nb_rx_queue >= MAX_RX_QUEUE_PER_PORT) {
            fprintf(stderr, 
                "Error: too many queues (%u) for lcore: %u\n", 
                (unsigned)nb_rx_queue+1, (unsigned)lcore);
            exit(-1);
        } else {
            lcore_conf[lcore].rx_queue_list[nb_rx_queue].port_id = 
                lcore_params[lcore].port_id;
            lcore_conf[lcore].rx_queue_list[nb_rx_queue].queue_id = 
                lcore_params[lcore].queue_id;
            lcore_conf[lcore].n_rx_queue++;
        }

    }

    return 0;
}

/* init mem */
static int
init_mem(unsigned nb_mbuf)
{
    lcore_conf_t qconf;
    int          socket_id;
    unsigned     lcore_id;
    char         s[64];

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        /* skip the disabled lcores */
        if (rte_lcore_is_enabled(lcore_id) == 0) 
            continue;

        if (numa_on) 
            socket_id = rte_lcore_to_socket_id(lcore_id);
        else 
            socket_id = 0;

        if (socket_id >= NB_SOCKETS) {
            rte_exit(EXIT_FAILURE, 
                "Socket %d of lcore %u is out of range %d\n", 
                socket_id, lcore_id, NB_SOCKETS );
        }

        if (pktmbuf_pool[socket_id] == NULL) {
            snprintf(s, sizeof(s), "mbuf_pool_%d", socket_id);
            pktmbuf_pool[socket_id] = 
                rte_mempool_create(s, nb_mbuf, 
                    MBUF_SIZE, MEMPOOL_CACHE_SIZE,
                    sizeof(struct rte_pktmbuf_pool_private),
                    rte_pktmbuf_pool_init, NULL,
                    rte_pktmbuf_init, NULL,
                    socket_id, 0);
            if (pktmbuf_pool[socket_id] == NULL) {
                rte_exit(EXIT_FAILURE, 
                    "Cannot init mbuf pool on socket %d\n", socket_id);
            } else {
                printf("Allocated mbuf pool on socket %d\n", socket_id);
            }

#ifdef (LOOKUP_METHOD == LOOKUP_LPM)
            setup_lpm(socket_id);
#elif
            setup_hash(socket_id);
#endif /* LOOKUP_METHOD for setup hash/lpm */

        }

        qconf = &lcore_conf[lcore_id];
        qconf->ipv4_lookup_struct = ipv4_l3fwd_lookup_struct[socket_id];

    }

    return 0;
}


/* check lcore params */
static int
check_lcore_params(void)
{
    uint8_t  queue, lcore;
    uint16_t i;
    int      socket_id;

    for (i = 0; i < nb_lcore_params; i++) {
        queue = lcore_params[i].queue_id;
        if (queue >= MAX_RX_QUEUE_PER_PORT) {
            printf("Invalid queue number: %hhu\n", queue);
            return -1;
        }
        
        lcore = lcore_params[i].lcore_id;
        if (!rte_lcore_is_enabled(lcore)) {
            printf("Error: lcore %hhu is not enabled in lcore mask\n",
                lcore);
            return -1;
        }
        
        socket_id = rte_lcore_to_socket_id(lcore);
        if ( socket_id != 0 && numa_on == 0) ) {
            printf("Warning: lcore %hhu is on socket %d with numa off\n", 
                lcore, socket_id);
        }
    }

    return 0;
}

/* check port config */
static int 
check_port_config(const unsigned nb_port)
{
    unsigned port_id;
    uint16_t i;

    for (i = 0 ; i < nb_lcore_params; i++) {
        port_id = lcore_params[i].port_id;
        if (enabled_port_mask & (1 << port_id) == 0) {
            printf("Prot %u is not enabled in port mask\n", port_id);
            return -1;
        }
        if (port_id >= nb_port) {
            printf("Port %u is not present on the board\n", port_id);
            return -1;
        }
    }
    return 0;
}


/* print mac address */
static void
print_ethaddr(const char *name. const struct ether_addr *eth_addr)
{
    char buf[ETHER_ADDR_FMT_SIZE];
    ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, eth_addr);
    printf("%s%s\n", name, buf);
}

/* check the link status of all ports in up to 9s, 
 * and print them finally */
static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (100ms * 90) in total */
    uint8_t port_id, count, all_ports_up, print_flag = 0;
    static rte_eth_link link;

    printf("\nChecking link status\n");
    fflush(stdout);
    for (count = 0; count < MAX_CHECK_TIME; count++) {
        all_ports_up = 1;
        for (port_id = 0; port_id < port_num; port_id++) {
            /* skip unused port */
            if ( (port_mask & (1 << port_id)) == 0 ) {
                continue;
            }

            /* get the status */
            memset(&link, 0, sizeof(link));
            /* non-blocking version */
            rte_eth_link_get_nowait(port_id, &link);

            /* print link status if flag set */
            if (print_flag == 1) {
                if (link.link_status) {
                    printf("Port %d Link Up - speed %u Mbps - %s.\n",
                        (uint8_t)port_id,
                        (unsigned)link.link_speed, 
                        (link.link_duplex == ETH_LINK_FULL_DUPLEX) ? 
                        ("full-dupelx") : ("half-duplex") );
                } else {
                    printf("Port %u Link Down.\n", (uint8_t)port_id);
                }
                continue;
            }

            /* clear all_ports_up flag if any link down */
            if (link.link_status == 0) {
                all_ports_up = 0;
                break;
            }
        }

        /* after finally print all link status, get out */
        if (print_flag == 1) 
            break;

        if (all_ports_up == 0) {
            printf(".");
            fflush(stdout);
            rte_delay_ms(CHECK_INTERVAL);
        }

        /* set the print flag if all ports up or timeout */
        if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
            print_flag = 1;
            printf("Done!\n");
        }
    }
}

/* config dpdk */
static int 
config_dpdk()
{
    unsigned int i;
    /* set enable_Port_mask */
    enabled_port_mask = 0;
    for (i = 0; i < m_config.num_of_nics_enabled; i++) {
        enabled_port_mask |= (1 << i);
    }

    /* set promiscuous_on */
    promiscuous_on = m_config.promiscuous_on;

    /* set numa_on */
    numa_on = m_config.numa_on;

    /* TODO: 
     * jumbo_frame
     * max_pkt_len */
    
    /* init the lcore_params */
    init_lcore_params(num_of_nics_enabled, 
        m_config.num_rx_queue_per_lcore, 
        m_config.num_cores);

    /* set rss key: use toepliz */
    static const uint8_t toepliz_key[40] = {
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A
    };

    static const uint8_t mtcp_key[40] = {
        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05
    };
    port_conf.rx_adv_conf.rss_conf.rss_key = (uint8_t *)&key;
    port_conf.rx_adv_conf.rss_conf.rss_key_len = sizeof(key);
}

/* init_dpdk */
static int
init_dpdk()
{
    lcore_conf_t            qconf;
    struct rte_eth_dev_info dev_info;
    int                     ret;
    unsigned                nb_ports;
    uint16_t                queue_id;
    unsigned                lcore_id;
    uint32_t                n_tx_queue;
    uint32_t                nb_lcores;
    uint8_t                 port_id;
    uint8_t                 nb_rx_queue;
    uint8_t                 queue;
    uint8_t                 socket_id;

    /* init EAL, done in config module */

    /* config such features:
     * -p              : enabled_port_mask
     * -P              : promiscuous_on
     * --config        : lcore_params, and nb_lcore_params
     * --no_numa       : numa_on = 1
     * --enable-jumbo  : port_conf.rxmode.jumbo_frame = 1
     * --max-pkt-len   : port_conf.rxmode.max_rx_pkt_len = val 
     * --hash-entry-num: hash_entry_num = val*/
    ret = config_dpdk();
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Invalid config.");
    }

    if (check_lcore_params() < 0) {
        rte_exit(EXIT_FAILURE, "check_lcore_params failed.\n")
    }

    ret = init_lcore_rx_queue();
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "init_lcore_params failed.\n");
    }

    nb_ports = rte_eth_dev_count();
    if (nb_ports > RTE_MAX_ETHPORTS) {
        nb_ports = RTE_MAX_ETHPORTS;
    }

    if (check_port_config(nb_ports) < 0) {
        rte_exit(EXIT_FAILURE, "check_port_config failed.\n");
    }

    nb_lcores = rte_lcore_count();

    /* init all ports */
    for (port_id; port_id < nb_ports; port_id++) {
        /* skip unused port */
        if ((enabled_port_mask & (1 << port_id)) == 0) {
            printf("Skipping unused port %d\n", port_id);
            continue;
        }

        /* init port */
        printf("Initializing port %d ...\n", port_id);
        fflush(stdout);

        nb_rx_queue = get_port_n_rx_queues(port_id);
        n_tx_queue  = m_config.num_tx_queue;
        if (n_tx_queue > MAX_TX_QUEUE_PER_PORT) {
            n_tx_queue = MAX_TX_QUEUE_PER_PORT;
        }
        ret = rte_eth_dev_configure(port_id, nb_rx_queue, 
            (uint16_t)n_tx_queue, &port_conf);
        if (ret < 0) {
            rte_exit(EXIT_FAILURE, "Cannot configure device:"
                " err=%d, port=%d", ret, port_id);
        } 

        printf("Created queues: nb_rxq=%d, nb_txq=%u. ", 
            nb_rx_queue, (unsigned)n_tx_queue);
        rte_eth_macaddr_get(port_id, &ports_eth_addr[port_id]);
        print_ethaddr("Address:", &ports_eth_addr[port_id]);
        printf(", ");


        /* prepare dst and src MACs for each port. 
         * TODO? why????? */
        *(uint64_t *)(val_eth + port_id) = 
            ETHER_LOCAL_ADMIN_ADDR + ((uint64_t)port_id << 40);
        ether_addr_copy(&ports_eth_addr[port_id], 
            (struct ether_addr *)(val_eth + port_id) + 1);

        /* init memory */
        ret = init_mem(NB_MBUF);
        if (ret < 0) {
            rte_exit(EXIT_FAILURE, "init_mem failed.\n");
        }

        /* init one TX queue per couple */
        queue_id = 0;
        for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
            /* skip unused lcore */
            if (rte_lcore_is_enabled(lcore_id) == 0) {
                printf("Skipping unused lcore %u.\n", lcore_id);
                continue
            }

            if (numa_on) {
                socket_id = (uint8_t)rte_lcore_to_socket_id(lcore_id);
            } else {
                socket_id = 0;
            }

            printf("txq=%u,%d,%d\n", lcore_id, queue_id, socket_id);
            fflush(stdout);

            rte_eth_dev_info_get(port_id, &dev_info);
            txconf = &dev_info.default_txconf;
            if (port_conf.rxmode.jumbo_frame) {
                txconf->txq_flags = 0;
            }
            ret = rte_eth_tx_queue_setup(port_id, queue_id, 
                nb_txd, socket_id, txconf);
            if (ret < 0) {
                rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: "
                    "err=%d, port=%u", ret, port_id);
            }
            qconf = &lcore_conf[lcore_id];
            qconf->tx_queue_id[port_id] = queue_id;
            queue_id++;

        }

        printf("\n");
    }

    /* Init RX queues */
    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        /* skip unused lcore */
        if (rte_lcore_is_enabled(lcore_id) == 0) {
            printf("Skipping unused lcore %u.\n", lcore_id);
            continue;
        }

        qconf = &lcore_conf[lcore_id];
        printf("Initializing rx queues on lcore %u ... \n", lcore_id);
        fflush(stdout);

        /* init RX queue */
        for (queue = 0; queue < qconf->n_rx_queue; queue++) {
            port_id = qconf->rx_queue_list[queue].port_id;
            queue_id = qconf->rx_queue_list[queue].queue_id;

            if (numa_on) {
                socket_id = (uint8_t)rte_lcore_to_socket_id(lcore_id);
            } else {
                socket_id = 0;
            }

            printf("rxq=%d,%d,%d\n", port_id, queue_id, socket_id);
            fflush(stdout);

            ret = rte_eth_rx_queue_setup(port_id, queue_id, 
                nb_rxd, socket_id, NULL, pktmbuf_pool[socket_id]);
            if (ret < 0) {
                rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: "
                    "err=%d, port=%d", ret, q.port_id);
            }
        }
    }

    printf("\n");

    /* start ports */
    for(port_id = 0; port_id < nb_ports; port_id++) {
        /* skip unused port */
        if ((enabled_port_mask & (1 << port_id)) == 0) {
            printf("Skipping unused port %d\n", port_id);
            continue;
        }

        /* start devide */
        printf("Starting port %d ... \n", port_id);
        ret = rte_eth_dev_start(port_id);
        if (ret < 0) {
            rte_exit(EXIT_FAILURE, "rte_eth_dev_start: "
                "err=%d, port=%d\n", ret, port_id);
        }

        /* If enabled, put device in promiscuous mode.
         * This allows IO forwarding mode to forward packets
         * to itself through 2 cross connected ports of the
         * target machine. */
        if (promiscuous_on) {
            rte_eth_promiscuous_enable(port_id);
        }
    }

    /* check all ports link status */
    check_all_ports_link_status((uint8_t)nb_ports, enabled_port_mask);

    /* launch per-locre init on each lcore */
    rte_eal_mp_remote_launch(main_loop, NULL, CALL_MASTER);
    RTE_LCORE_ROREACH_SLAVE(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0 )
            return -1;
    }
    0
    return 0;
}


/* main_loop */
static int
main_loop(__attribute__((unused)) void *dummy)
{
    rte_mbuf_t   pkts_burst[MAX_PKT_BURST];
    unsigned     lcore_id;
    uint64_t     pre_tsc, cur_tsc, diff_tsc;
    int          i, j, nb_rx;
    uint8_t      port_id, queue_id;
    lcore_conf_t qconf;

    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) /
        US_PER_S * BURST_TX_DRAIN_US;

#ifdef ((LOOKUP_METHOD == LOOKUP_LPM) && (ENABLE_MULTI_BUFFER_OPTIMIZE == 1))
    int32_t   k;
    uint16_t  dlp;
    uint16_t  *lp;
    uint16_t  dst_port[MAX_PKT_BURST];
    __m128i   dip[MAX_PKT_BURST / FWDSTEP];
    uint32_t  flag[MAX_PKT_BURST / FWDSTEP];
    uint16_t  pnum[MAX_PKT_BURST + 1];
#endif /* LOOKUP_METHOD and ENABLE_MULTI_BUFFER_OPTIMIZE */

    pre_tsc = 0;

    lcore_id = rte_lcore_id();
    qconf = &lconf_conf[lcore_id];

    if (qconf->n_rx_queue == 0) {
#ifdef DEBUG
        printf("lcore %u has nothing to do\n", lcore_id);
#endif
        return 0;
    }

#ifdef DEBUG
    printf("Entering main loop on lcore %u\n", lcore_id);
#endif

    for (i = 0; i < qconf->n_rx_queue; i++) {
        port_id = qconf->rx_queue_list[i].port_id;
        queue_id = qconf->rx_queue_list[i].queue_id;
#ifdef DEBUG
        printf("-- lcore_id=%u port_id=%hhu rx_queue_id=%hhu\n", 
            lcore_id, port_id, queue_id);
#endif
    }

    while(1) {
        /* get the time */
        cur_tsc = rte_rdtsc();

        /* TX burst queue drain */
        diff_tsc = cur_tsc - pre_tsc;
        if (unlikely(diff_tsc > drain_tsc)) {
            /* TODO: optimized it by using queueid */
            for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
                if (qconf->tx_mbufs[port_id].len == 0) {
                    continue;
                }

                send_burst(qconf, qconf->tx_mbufs[port_id].len, port_id);
                qconf->tx_mbufs[port_id].len = 0;
            }
            
            pre_tsc = cur_tsc;
        }


        /* Read pkts from RX queue */
        for (i = 0; i < qconf->n_rx_queue; i++) {
            port_id = qconf->rx_queue_list[i].port_id;
            queue_id = qconf->rx_queue_list[i].queue_id;
            nb_rx = rte_eth_rx_burst(port_id, queue_id, pkts_burst, 
                MAX_PKT_BURST);
            if (nb_rx == 0) {
                continue;
            }
#if (ENABLE_MULTI_BUFFER_OPTIMIZE == 1)
#if (LOOKUP_METHOD == LOOKUP_EXACT_MATCH)
            {
                /* send nb_rx - nb_rx%4 pkts in groups of 4 */
                int32_t n = RTE_ALIGN_FLOOR(nb_rx, 4);
                for (j = 0; j < n; j++) {
                    uint32_t ol_flags = pkts_burst[j]->ol_flags
                        & pkts_burst[j + 1]->ol_flags
                        & pkts_burst[j + 2]->ol_flags
                        & pkts_burst[j + 3]->ol_flags;
                    if (ol_flags & PKT_RX_IPV4_HDR) {
                        simple_ipv4_fwd_4pkts(&pkts_burst[j], 
                            port_id, qconf);
                    } else {
                        l3fwd_simple_forward(pkts_burst[j], 
                            port_id, qconf);
                        l3fwd_simple_forward(pkts_burst[j+1], 
                            port_id, qconf);
                        l3fwd_simple_forward(pkts_burst[j+2], 
                            port_id, qconf);
                        l3fwd_simple_forward(pkts_burst[j+3], 
                            port_id, qconf);
                    }
                }
                for (; j < nb_rx; j++) {
                    l3fwd_simple_forward(pkts_burst[j], 
                        port_id, qconf);
                }
    
            }
            
#elif (LOOKUP_METHOD == LOOKUP_LPM)
            {
                k = RTE_ALIGN_FLOOR(nb_rx, FWDSTEP);
                for (j = 0; j != k; j += FWDSTEP) {
                    processx4_step1(&pkts_burst[j], 
                        &dip[j / FWDSTEP],
                        &flag[j / FWDSTEP]);
                }

                k = RTE_ALIGN_FLOOR(nb_rx, FWDSTEP);
                for (j = 0; j != k; j += FWDSTEP) {
                    processx4_step2(qconf, dip[j / FWDSTEP], 
                        flag[j / FWDSTEP], port_id, 
                        &pkts_burst[j], &dst_port[j]);
                }

                /* finish pkt processing and group consecutive
                 * pkts with same dst port */
                k = RTE_ALIGN_FLOOR(nb_rx, FWDSTEP);
                if (k != 0) {
                    __m128i dp1, dp2;

                    lp = pnum;
                    lp[0] = 1;

                    processx4_step3(pkts_burst, dst_port);
                    /* dp1:<d[0], d[1], d[2], d[3], ...> */
                    dp1 = _mm_loadu_si128((__m128i*)dst_port);

                    for (j = FWDSTEP; j != k; j += FWDSTEP) {
                        processx4_step3(&pkts_burst[j], &dst_port[j]);
                        /* dp2:<d[j-3], d[j-2], d[j-1], d[j], ...> */
                        dp2 = _mm_loadu_si128((__m128i*)
                            &dst_port[j - FWDSTEP + 1]);
                        lp = port_groupx4(&pnum[j - FWDSTEP], 
                            lp, dp1, dp2);

                        /* dp1:<d[j], d[j+1], d[j+2], d[j+3], ...> */
                        dp1 = _mm_srli_si128(dp2, (FWDSTEP-1) * 
                            sizeof(dst_port[0]));
                    }

                    /* dp2:<d[j-3], d[j-2], d[j-1], d[j], ...> */
                    dp2 = _mm_shufflelo_epi16(dp1, 0xf9);
                    lp = port_groupx4(&pnum[j - FWDSTEP], 
                        lp, dp1, dp2);

                    /* remove values added by the last repeated dst port */
                    lp[0]--;
                    dlp = dst_port[j - 1];
                } else {
                    /* set dlp and lp to the never used values */
                    dlp = BAD_PORT - 1;
                    lp = pnum + MAX_PKT_BURST;
                }

                /* process up to last 3 pkts one by one */
                switch (nb_rx % FWDSTEP) {
                    case 3:
                        process_packet(qconf, pkts_burst[j], 
                            dst_port + j, port_id);
                        GROUP_PORT_STEP(dlp, dst_port, lp, pnum, j);
                        j++;
                    case 2:
                        process_packet(qconf, pkts_burst[j], 
                            dst_port + j, port_id);
                        GROUP_PORT_STEP(dlp, dst_port, lp, pnum, j);
                        j++;
                    case 1:
                        process_packet(qconf, pkts_burst[j], 
                            dst_port + j, port_id);
                        GROUP_PORT_STEP(dlp, dst_port, lp, pnum, j);
                        j++;
                }

                /* sned pkts out, through dst port.
                 * consecutive pkts with same dst port have been grouped
                 * free them when dst port is BAD_POIR */
                for (j = 0; j < nb_rx; j += k) {
                    int32_t  m;
                    uint16_t pn;

                    pn = dst_port[j];
                    k = pnum[j];
                    if (likely(pn != BAD_POIR)) {
                        send_packetsx4(qconf, pn, pkts_burst + j, k);
                    } else {
                        for (m = j; m != j +k ; m++) {
                            rte_pktmbuf_free(pkts_burst[m]);
                        }
                    }
                }
            }
#endif /* LOOKUP_METHOD */
#else /* ENABLE_MULTI_BUFFER_OPTIMIZE == 0 */
            /* prefetch first pkts */
            for (j = 0; j < PREFETCH_OFFSET && j < nb_rx; j++) {
                rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j], void*));
            }

            /* prefetch remaining pkts */
            for (j = 0; j < (nb_rx - PREFETCH_OFFSET); j++) {
                rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[
                    j + PREFETCH_OFFSET], void*));
            }

#endif /* ENABLE_MULTI_BUFFER_OPTIMIZE */



        }

    }

}