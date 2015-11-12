#include "hash.h"

#if (LOOKUP_METHOD == LOOKUP_EXACT_MATCH)

/* ipv4 hash crc */
inline uint32_t
ipv4_hash_crc(const void *data, __rte_unused uint32_t data_len,
    uint32_t init_val)
{
    const union ipv4_5tuple_host *k;
    uint32_t t;
    const uint32_t *p;

    k = data;
    t = k->proto;
    p = (const uint32_t *)&k->port_src;

#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
    init_val = rte_hash_crc_4byte(t, init_val);
    init_val = rte_hash_crc_4byte(k->ip_src, init_val);
    init_val = rte_hash_crc_4byte(k->ip_dst, init_val);
    init_val = rte_hash_crc_4byte(*p, init_val);
#else
    init_val = rte_jhash_1word(t, init_val);
    init_val = rte_jhash_1word(k->ip_src, init_val);
    init_val = rte_jhash_1word(k->ip_dst, init_val);
    init_val = rte_jhash_1word(*p, init_val);
#endif
    return (init_val);
}


/* get ipv4 dest port */
inline uint8_t
get_ipv4_dst_port(void *ipv4_hdr, uint8_t port_id, 
    lookup_struct_t ipv4_l3fwd_lookup_struct)
{
    int ret = 0;
    union ipv4_5tuple_host key;

    ipv4_hdr = (uint8_t *)ipv4_hdr + 
        offsetof(struct ipv4_hdr, time_to_live);
    __m128i data = _mm_loadu_si128((__m128i*)(ipv4_hdr));

    /* get 5 tuple: dst port, src port, dstIP, srcIP, and proto*/
    key.xmm = _mm_and_si128(data, mask0);
    
    /* find destination port */
    rte = rte_hash_lookup(ipv4_l3fwd_lookup_struct, (const void *)&key);

    return (uint8_t)( (ret < 0)? port_id : ipv4_l3fwd_out_if[ret] );
}

/* simple ipv4  fwd 4pkts */
inline void
simple_ipv4_fwd_4pkts(struct rte_mbuf_t m[4], uint8_t port_id,
    lcore_conf_t qconf)
{
    ether_hdr_t            eth_hdr[4];
    ipv4_hdr_t             ipv4_hdr[4];
    void                   *d_addr_bytes[4];
    uint8_t                dst_port[4];
    int32_t                ret[4];
    union ipv4_5tuple_host key[4];
    __m128i                data[4];

    eth_hdr[0] = rte_pktmbuf_mtod(m[0], struct ether_hdr_t);
    eth_hdr[1] = rte_pktmbuf_mtod(m[1], struct ether_hdr_t);
    eth_hdr[2] = rte_pktmbuf_mtod(m[2], struct ether_hdr_t);
    eth_hdr[3] = rte_pktmbuf_mtod(m[3], struct ether_hdr_t);

    /* handle ipv4 headers */
    ipv4_hdr[0] = (ipv4_hdr_t)(rte_pktmbuf_mtod(m[0], uchar *) 
        + sizeof(struct ether_hdr) );
    ipv4_hdr[1] = (ipv4_hdr_t)(rte_pktmbuf_mtod(m[1], uchar *) 
        + sizeof(struct ether_hdr) );
    ipv4_hdr[2] = (ipv4_hdr_t)(rte_pktmbuf_mtod(m[2], uchar *) 
        + sizeof(struct ether_hdr) );
    ipv4_hdr[3] = (ipv4_hdr_t)(rte_pktmbuf_mtod(m[3], uchar *) 
        + sizeof(struct ether_hdr) );

#ifdef DO_RFC_1812_CHECKS
    /* check the pkt is valid */
    uint8_t valid_mask - MASK_ALL_PKTS;
    if (is_valid_ipv4_pkt(ipv4_hdr[0], m[0]->pkt_len) < 0) {
        rte_pktmbuf_free(m[0]);
        valid_mask &= EXECLUDE_1ST_PKT;
    }
    if (is_valid_ipv4_pkt(ipv4_hdr[1], m[1]->pkt_len) < 0) {
        rte_pktmbuf_free(m[1]);
        valid_mask &= EXECLUDE_2ND_PKT;
    }
    if (is_valid_ipv4_pkt(ipv4_hdr[2], m[2]->pkt_len) < 0) {
        rte_pktmbuf_free(m[2]);
        valid_mask &= EXECLUDE_3RD_PKT;
    }
    if (is_valid_ipv4_pkt(ipv4_hdr[3], m[3]->pkt_len) < 0) {
        rte_pktmbuf_free(m[3]);
        valid_mask &= EXECLUDE_4TH_PKT;
    }

    if (unlikely(valid_mask != MASK_ALL_PKTS)) {
        if (valid_mask == 0) {
            return ;
        } else {
            uint8_t i = 0;
            for (int i = 0; i < 4; i++) {
                if ((0x1 << i) & valid_mask) {
                    l3fwd_simple_forward(m[i], port_id, qconf);
                }
            }
            return ;
        }
    }
#endif /* DO_RFC_1812_CHECKS */

    data[0] = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m[0], uchar*) +
        sizeof(struct ether_hdr) + offsetof(struct ipv4_hdr, time_to_live)));
    data[1] = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m[1], uchar*) +
        sizeof(struct ether_hdr) + offsetof(struct ipv4_hdr, time_to_live)));
    data[2] = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m[2], uchar*) +
        sizeof(struct ether_hdr) + offsetof(struct ipv4_hdr, time_to_live)));
    data[3] = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m[3], uchar*) +
        sizeof(struct ether_hdr) + offsetof(struct ipv4_hdr, time_to_live)));

    key[0].xmm = _mm_and_si128(data[0], mask0);
    key[1].xmm = _mm_and_si128(data[1], mask0);
    key[2].xmm = _mm_and_si128(data[2], mask0);
    key[3].xmm = _mm_and_si128(data[3], mask0);

    const void *key_array[4] = {&key[0], &key[1], &key[2], &key[3]};
    rte_hash_lookup_multi(qconf->ipv4_lookup_struct, &key_array[0], 4, ret);
    dst_port[0] = (uint8_t)((ret[0] < 0) ? 
        port_id : ipv4_l3fwd_out_if[ret[0]]);
    dst_port[1] = (uint8_t)((ret[1] < 0) ? 
        port_id : ipv4_l3fwd_out_if[ret[1]]);
    dst_port[2] = (uint8_t)((ret[2] < 0) ? 
        port_id : ipv4_l3fwd_out_if[ret[2]]);
    dst_port[3] = (uint8_t)((ret[3] < 0) ? 
        port_id : ipv4_l3fwd_out_if[ret[3]]);

    if (dst_port[0] >= RTE_MAX_ETHPORTS || 
        (enabled_port_mask & (1 << dst_port[0])) == 0)
        dst_port[0] = port_id;
    if (dst_port[1] >= RTE_MAX_ETHPORTS || 
        (enabled_port_mask & (1 << dst_port[1])) == 0)
        dst_port[1] = port_id;
    if (dst_port[2] >= RTE_MAX_ETHPORTS || 
        (enabled_port_mask & (1 << dst_port[2])) == 0)
        dst_port[2] = port_id;
    if (dst_port[3] >= RTE_MAX_ETHPORTS || 
        (enabled_port_mask & (1 << dst_port[3])) == 0)
        dst_port[3] = port_id;

    /* 02:00:00:00:00:00:xx */
    d_addr_bytes[0] = &eth_hdr[0]->d_addr.addr_bytes[0];
    d_addr_bytes[1] = &eth_hdr[1]->d_addr.addr_bytes[0];
    d_addr_bytes[2] = &eth_hdr[2]->d_addr.addr_bytes[0];
    d_addr_bytes[3] = &eth_hdr[3]->d_addr.addr_bytes[0];
    *((uint64_t *)d_addr_bytes[0]) = 0x000000000002 + (
        (uint64_t)dst_port[0] << 40);
    *((uint64_t *)d_addr_bytes[1]) = 0x000000000002 + (
        (uint64_t)dst_port[1] << 40);
    *((uint64_t *)d_addr_bytes[2]) = 0x000000000002 + (
        (uint64_t)dst_port[2] << 40);
    *((uint64_t *)d_addr_bytes[3]) = 0x000000000002 + (
        (uint64_t)dst_port[3] << 40);

#ifdef DO_RFC_1812_CHECKS
    /* update time to live and header checksum */
    --(ipv4_hdr[0]->time_to_live);
    --(ipv4_hdr[1]->time_to_live);
    --(ipv4_hdr[2]->time_to_live);
    --(ipv4_hdr[3]->time_to_live);
    ++(ipv4_hdr[0]->hdr_checksum);
    ++(ipv4_hdr[1]->hdr_checksum);
    ++(ipv4_hdr[2]->hdr_checksum);
    ++(ipv4_hdr[3]->hdr_checksum);
#endif /* DO_RFC_1812_CHECKS */

    /* src addr */
    ether_addr_copy(&ports_eth_addr[dst_port[0]], &eth_hdr[0]->s_addr);
    ether_addr_copy(&ports_eth_addr[dst_port[1]], &eth_hdr[1]->s_addr);
    ether_addr_copy(&ports_eth_addr[dst_port[2]], &eth_hdr[2]->s_addr);
    ether_addr_copy(&ports_eth_addr[dst_port[3]], &eth_hdr[3]->s_addr);

    /* send single packet */
    send_single_packet(m[0], (uint8_t)dst_port[0]);
    send_single_packet(m[1], (uint8_t)dst_port[1]);
    send_single_packet(m[2], (uint8_t)dst_port[2]);
    send_single_packet(m[3], (uint8_t)dst_port[3]);

}



/* simple ipv4 fwd 1 pkt */
inline __attribute__((always_inline)) void
l3fwd_simple_forward(rte_mbuf_t m, uint8_t port_id, lcore_conf_t qconf)
{
    ether_hdr_t  eth_hdr;
    ipv4_hdr_t   ipv4_hdr;
    void         *d_addr_bytes;
    uint8_t      dst_port;

    eth_hdr = rte_pktmbuf_mtod(m, ether_hdr_t);

    /* handle ipv4 headers */
    ipv4_hdr = (ipv4_hdr_t)(rte_pktmbuf_mtod(m, uchar*) + 
       sizeof(struct ether_hdr));
    
#ifdef DO_RFC_1812_CHECKS
    /* check the pkt is valid */
    if (is_valid_ipv4_pkt(ipv4_hdr, m->pkt_len) < 0) {
        rte_pktmbuf_free(m);
        return ;
    }
#endif /* DO_RFC_1812_CHECKS */

    dst_port = get_ipv4_dst_port(ipv4_hdr, port_id, 
        qconf->ipv4_lookup_struct);
    if (dst_port > RTE_MAX_ETHPORTS || 
        (enabled_port_mask & (1 << dst_port)) == 0)
        dst_port = port_id;

    /* 02:00:00:00:00:00:xx */
    d_addr_bytes = &eth_hdr->d_addr.addr_bytes[0];
    *((uint64_t *)d_addr_bytes) = ETHER_LOCAL_ADMIN_ADDR + 
        ((uint64_t)dst_port << 40);

#ifdef DO_RFC_1812_CHECKS
    /* update time to live and header checksum */
    --(ipv4_hdr->time_to_live);
    ++(ipv4_hdr->hdr_checksum);
#endif /* DO_RFC_1812_CHECKS */

    /* src addr */
    ether_addr_copy(&ports_eth_addr[dst_port], &eth_hdr->s_addr);

    send_single_packet(m, dst_port);

}

#ifdef DO_RFC_1812_CHECKS
/* 
 *      the cons of rfc1812
 * - IP version number must be 4
 * - IP header length field must be >= 20B(5 words)
 * - IP total length field must be >= IP header length field
 * if it is a invalid pkt, set dest port to BAD_PORT
 */
inline __attribute__((always_inline)) void
rfc1812_process(ipv4_hdr_t ipv4_hdr, uint16_t *dp, uint32_t flags)
{
    uint8_t ihl;

    if ((flags & PKT_RX_IPV4_HDR) != 0) {
        ihl = ipv4_hdr->version_ihl - IPV4_MIN_VER_IHL;

        ipv4_hdr->time_to_live--;
        ipv4_hdr->hdr_checksum++;

        if (ihl > IPV4_MAX_VER_IHL_DIFF ||
            ( (uint8_t)ipv4_hdr->total_length == 0 &&
            ipv4_hdr->total_length < IPV4_MIN_LEN_BE) ) {
            dp[0] = BAD_PORT;
        }
    }
}
#endif /* DO_RFC_1812_CHECKS */


/* convert ipv4 tuple into host format */
void convert_ipv4_5tuple(ipv4_5tuple_t key1, 
    ipv4_5tuple_host_t, key2)
{
    key2->ip_dst = rte_cpu_to_be_32(key1->ip_dst);
    key2->ip_src = rte_cpu_to_be_32(key1->ip_src);
    key2->port_dst = rte_cpu_to_be_16(key1->port_dst);
    key2->port_src = rte_cpu_to_be_16(key1->port_src);
    key2->proto = key1->proto;
    key2->pad0 = 0;
    key2->pad1 = 0;
    return;
}

/* init ipv4_l3fwd_route_array */
int
init_ipv4_l3fwd_route_array(void)
{
    /* TODO */
}

/* populate ipv4 few flow into table */
inline void
populate_ipv4_few_flow_into_table(const rte_hash_t h)
{
    uint32_t i;
    int32_t  ret;
    uint32_t array_len = ipv4_l3fwd_num_routes;
        
    mask0 = _mm_set_epi32(ALL_32_BITS, ALL_32_BITS, 
        ALL_32_BITS, BIT_8_TO_15);
    for (i = 0; i < array_len; i++) {
        struct ipv4_l3fwd_route entry;
        union ipv4_5tuple_host  newkey;
    
        entry = ipv4_l3fwd_route_array[i];
        convert_ipv4_5tuple(&entry.key, &newkey);
        ret = rte_hash_add_key(h, (void *)&newkey);
        if (ret < 0) {
            rte_exit(EXIT_FAILURE, "Unable to add entry %" PRIu32
                " to the l3fwd hash.\n", i);
        }
        ipv4_l3fwd_out_if[ret] = entry.if_out;
    }
    printf("Hash: Adding 0x%" PRIx32 " keys\n", array_len);

}

/* populate ipv4 many flow into table */
#define NUMBER_PORT_USED 4
inline void
populate_ipv4_many_flow_into_table(const rte_hash_t h, 
    unsigned int nr_flow)
{
    unsigned i;
    int32_t  ret;
    uint8_t  a,b,c;
    
    mask0 = _mm_set_epi32(ALL_32_BITS, ALL_32_BITS,
        ALL_32_BITS, BIT_8_TO_15);
    for (i = 0; i < nr_flow; i++) {
        struct ipv4_l3fwd_route entry;
        union ipv4_5tuple_host  newkey;

        /* why? */
        a = (uint8_t) ((i/NUMBER_PORT_USED) % BYTE_VALUE_MAX);
        b = (uint8_t) (((i/NUMBER_PORT_USED)/BYTE_VALUE_MAX)%
            BYTE_VALUE_MAX);
        c = (uint8_t) ((i/NUMBER_PORT_USED)/
            (BYTE_VALUE_MAX*BYTE_VALUE_MAX));

        /* create the ipv4 exact match flow */
        memset(&entry, 0, sizeof(entry));
        switch ( i & (NUMBER_PORT_USED - 1) ) {
            case 0:
                entry = ipv4_l3fwd_route_array[0];
                entry.key.ip_dst = IPv4(101,c,b,a);/*Why?*/
                break;
            case 1:
                entry = ipv4_l3fwd_route_array[1];
                entry.key.ip_dst = IPv4(201,c,b,a);
                break;
            case 2:
                entry = ipv4_l3fwd_route_array[2];
                entry.key.ip_dst = IPv4(111,c,b,a);
                break;
            case 0:
                entry = ipv4_l3fwd_route_array[3];
                entry.key.ip_dst = IPv4(211,c,b,a);
                break;

        };

        convert_ipv4_5tuple(&entry.key, &newkey);
        ret = rte_hash_add_key(h, (void *)&newkey);
        if (ret < 0) {
            rte_exit(EXIT_FAILURE, "Unable to add entry %u\n", i);
        }

        ipv4_l3fwd_out_if[ret] = (uint8_t) entry.if_out;
    }
    printf("Hash: Adding 0x%x keys\n", nr_flow);
}

/* setup hash method for lookup */
void
setup_hash(int socket_id)
{
    struct rte_hash_parameters ipv4_l3fwd_hash_params =
    {
        .name = NULL,
        .entries = L3FWD_HASH_ENTRIES,
        .bucket_entries = 4,
        .key_len = sizeof(union ipv4_5tuple_host),
        .hash_func = ipv4_hash_crc,
        .hash_func_init_val = 0,
    };

    char s[64];

    /* create ipv4 hash */
    snprintf(s, sizeof(s), "ipv4_l3fed_hash_%d", socket_id);
    ipv4_l3fwd_hash_params.name = s;
    ipv4_l3fwd_hash_params.socket_id = socket_id;
    ipv4_l3fwd_lookup_struct[socket_id] = 
        rte_hash_create(&ipv4_l3fwd_hash_params);
    if (ipv4_l3fwd_lookup_struct[socket_id] == NULL) {
        rte_exit(EXIT_FAILURE, "Unable to create the l3fwd hash"
            " on socket %d\n", socket_id);
    }

    if (hash_entry_number != HASH_ENTRY_NUMBER_DEFAULT) {
        /* For testing hash matching with a large number of flows we
         * generate millions of IP-5tuples with an incremented dst 
         * address to init the hash table. */
        populate_ipv4_many_flow_into_table(
            ipv4_l3fwd_lookup_struct[socket_id], hash_entry_number);
    } else {
        populate_ipv4_few_flow_into_table(
            ipv4_l3fwd_lookup_struct[socket_id]);
    }
}

#endif /* LOOKUP_METHOD == LOOKUP_EXACT_MATCH */
