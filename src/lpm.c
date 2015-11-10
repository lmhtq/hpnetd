#include "lpm.h"
#include "forward.h"
#include "config.h"

#if (LOOKUP_METHOD == LOOKUP_LPM)

/* get ipv4 dst port */
static inline uint8_t
get_ipv4_dst_port(void *ipv4_hdr, uint8_t port_id, 
    lookup_struct_t ipv4_l3fwd_lookup_struct)
{
    uint8_t next_hop;
    return (uint8_t) (
        (rte_lpm_lookup(
            ipv4_l3fwd_lookup_struct, 
            rte_be_to_cpu_32(((struct ipv4_hdr *)ipv4_hdr)->dst_addr),
                 &next_hop) == 0) ? next_hop : port_id
        );
}

/* for enable multiple buffer optimize */
#ifdef ENABLE_MULTI_BUFFER_OPTIMIZE == 1
static inline __attribute__((always_inline)) uint16_t
get_dst_port(const lcore_conf_t qconf, rte_mbuf_t pkt, 
    uint32_t dst_ipv4, uint8_t port_id)
{
    uint8_t next_hop;

    if (rte_lpm_lookup(qconf->ipv4_lookup_struct, 
        dst_ipv4, &next_hop) != 0) 
        next_hop = port_id;

    return next_hop;
}

static inline void
process_packet(lcore_conf_t qconf, rte_mbuf_t pkt,
    uint16_t *dst_port, uint8_t port_id)
{
    ether_hdr_t eth_hdr;
    ipv4_hdr_t  ipv4_hdr;
    uint32_t    dst_ipv4;
    uint16_t    dp;
    __m128i     te, ve;

    eth_hdr = rte_pktmbuf_mtod(pkt, ether_hdr_t);
    ipv4_hdr = (ipv4_hdr_t)(eth_hdr + 1);

    dst_ipv4 = ipv4_hdr->dst_addr;
    dst_ipv4 = rte_be_to_cpu_32(dst_ipv4);
    dp = get_dst_port(qconf, pkt, dst_ipv4, port_id);

    te = _mm_load_si128((__m128i *)eth_hdr);
    ve = val_eth[dp];

    dst_port[0] = dp;
    rfc1812_process(ipv4_hdr, dst_port, pkt->ol_flags);

    te = _mm_blend_epi16(te, ve, MASK_ETH);
    _mm_store_si128((__m128i *)eth_hdr, te);
}

/* read ol_flags and dst IPV4 address from 4 mubfs */
static inline void
processx4_step1(rte_mbuf_t pkt[FWDSTEP], __m128i *dip, uint32_t *flag)
{
    ipv4_hdr_t  ipv4_hdr;
    ether_hdr_t eth_hdr;
    uint32_t    x0, x1, x2, x3;

    eth_hdr = rte_pktmbuf_mtod(pkt[0], ether_hdr_t);
    ipv4_hdr = (ipv4_hdr_t)(eth_hdr + 1);
    x0 = ipv4_hdr->dst_addr;
    flag[0] = pkt[0]->ol_flags & PKT_RX_IPV4_HDR;

    eth_hdr = rte_pktmbuf_mtod(pkt[1], ether_hdr_t);
    ipv4_hdr = (ipv4_hdr_t)(eth_hdr + 1);
    x0 = ipv4_hdr->dst_addr;
    flag[0] &= pkt[1]->ol_flags & PKT_RX_IPV4_HDR;

    eth_hdr = rte_pktmbuf_mtod(pkt[2], ether_hdr_t);
    ipv4_hdr = (ipv4_hdr_t)(eth_hdr + 1);
    x0 = ipv4_hdr->dst_addr;
    flag[0] &= pkt[2]->ol_flags & PKT_RX_IPV4_HDR;

    eth_hdr = rte_pktmbuf_mtod(pkt[3], ether_hdr_t);
    ipv4_hdr = (ipv4_hdr_t)(eth_hdr + 1);
    x0 = ipv4_hdr->dst_addr;
    flag[0] &= pkt[3]->ol_flags & PKT_RX_IPV4_HDR;

    dip[0] = _mm_set_epi32(x3, x2, x1, x0);
}

/* lookup into LPM fro dst port. If lookup fails, 
 * use incoming port(port_id) as dst port */
static inline void
processx4_step2(const lcore_conf_t qconf, __m128i dip, uint32_t flag, 
    uint8_t port_id, rte_mbuf_t pkt[FWDSTEP], uint16_t dst_port[FWDSTEP])
{
    rte_xmm_t dst;
    const __m128i bswap_mask = _mm_set_epi8(12,13,14,15, 
        8,9,10,11, 
        4,5,6,7,
        0,1,2,3);

    /* Byte swap 4 IPV4 addresses */
    dip = _mm_shuffle_epi8(dip, bswap_mask);

    /* if all 4 pkt are ipv4 */
    if (likely(flag != 0)) {
        rte_lpm_lookupx4(qconf->ipv4_lookup_struct, dip, 
            dst_port, port_id);
    }
}

/* update src and dest mac address in ethernet header.
 * perfom rfc1812 checks and update for ipv4 packets */
static inline void
processx4_step3(rte_mbuf_t pkt[FWDSTEP], uint16_t dst_port[FWDSTEP])
{
    __m128i te[FWDSTEP];
    __m128i ve[FWDSTEP];
    __m128i *p[FWDSTEP];

    p[0] = (rte_pktmbuf_mtod(pkt[0], __m128i *));
    p[1] = (rte_pktmbuf_mtod(pkt[1], __m128i *));
    p[2] = (rte_pktmbuf_mtod(pkt[2], __m128i *));
    p[3] = (rte_pktmbuf_mtod(pkt[3], __m128i *));

    ve[0] = val_eth[dst_port[0]];
    te[0] = _mm_load_si128(p[0]);

    ve[1] = val_eth[dst_port[1]];
    te[1] = _mm_load_si128(p[1]);
    
    ve[2] = val_eth[dst_port[2]];
    te[2] = _mm_load_si128(p[2]);
    
    ve[3] = val_eth[dst_port[3]];
    te[3] = _mm_load_si128(p[3]);

    /* update first 12 Bytes, keep rest bytes intact */
    te[0] = _mm_blend_epi16(te[0], ve[0], MASK_ETH);
    te[1] = _mm_blend_epi16(te[1], ve[1], MASK_ETH);
    te[2] = _mm_blend_epi16(te[2], ve[2], MASK_ETH);
    te[3] = _mm_blend_epi16(te[3], ve[3], MASK_ETH);

    _mm_store_si128(p[0], te[0]);
    _mm_store_si128(p[1], te[1]);
    _mm_store_si128(p[2], te[2]);
    _mm_store_si128(p[3], te[3]);

    rfc1812_process((ipv4_hdr_t)((ether_hdr_t)p[0] + 1), 
        &dst_port[0], pkt[0]->ol_flags);
    rfc1812_process((ipv4_hdr_t)((ether_hdr_t)p[1] + 1), 
        &dst_port[1], pkt[1]->ol_flags);
    rfc1812_process((ipv4_hdr_t)((ether_hdr_t)p[2] + 1), 
        &dst_port[2], pkt[2]->ol_flags);
    rfc1812_process((ipv4_hdr_t)((ether_hdr_t)p[3] + 1), 
        &dst_port[3], pkt[3]->ol_flags);

}

/* Group consecutive packets with the same dest port in burst of 4.
 * Suppose we have array of dest ports:
 * dst_port[] = {a,b,c,d,e,..}
 * dp1 should contain:<a,b,c,d>, dp2:<b,c,d,e>
 * Make 4 comparisions at once and the result is 4 bit mask
 * The mask is used as an index into prebuild array of pnum values */
static inline uint16_t *
port_groupx4(uint16_t pn[FWDSTEP + 1], uint16_t *lp, 
    __m128i dp1, __m128i dp2)
{
    static const struct
    {
        uint64_t pnum; /* prebuild 4 values for pnum */
        int32_t  idx;  /* index for new last updated element */
        uint16_t lpv;  /* add value to the last updated element */
    } gptbl[GRPSZ] = {
        {
            /* 0:a!=b,b!=c,c!=d,d!=e */
            .pnum = UINT64_C(0x0001000100010001),
            .idx  = 4,
            .lpv  = 0,
        },
        {
            /* 1:a==b,b!=c,c!=d,d!=e */
            .pnum = UINT64_C(0x0001000100010002),
            .idx  = 4,
            .lpv  = 1,
        },
        {
            /* 2:a!=b,b==c,c!=d,d!=e */
            .pnum = UINT64_C(0x0001000100020001),
            .idx  = 4,
            .lpv  = 0,
        },
        {
            /* 3:a==b,b==c,c!=d,d!=e */
            .pnum = UINT64_C(0x0001000100020003),
            .idx  = 4,
            .lpv  = 2,
        },
        {
            /* 4:a!=b,b!=c,c==d,d!=e */
            .pnum = UINT64_C(0x0001000200010001),
            .idx  = 4,
            .lpv  = 0,
        },
        {
            /* 5:a==b,b!=c,c==d,d!=e */
            .pnum = UINT64_C(0x0001000200010002),
            .idx  = 4,
            .lpv  = 1,
        },
        {
            /* 6:a!=b,b==c,c==d,d!=e */
            .pnum = UINT64_C(0x0001000200030001),
            .idx  = 4,
            .lpv  = 0,
        },
        {
            /* 7:a==b,b==c,c==d,d!=e */
            .pnum = UINT64_C(0x0001000200030004),
            .idx  = 4,
            .lpv  = 3,
        },
        {
            /* 8:a!=b,b!=c,c!=d,d==e */
            .pnum = UINT64_C(0x0002000100010001),
            .idx  = 3,
            .lpv  = 0,
        },
        {
            /* 9:a==b,b!=c,c!=d,d==e */
            .pnum = UINT64_C(0x0002000100010002),
            .idx  = 3,
            .lpv  = 1,
        },
        {
            /* 0xa(10):a!=b,b==c,c!=d,d==e */
            .pnum = UINT64_C(0x0002000100020001),
            .idx  = 3,
            .lpv  = 0,
        },
        {
            /* 0xb(11):a==b,b==c,c!=d,d==e */
            .pnum = UINT64_C(0x0002000100020003),
            .idx  = 3,
            .lpv  = 2,
        },
        {
            /* 0xc(12):a!=b,b!=c,c==d,d==e */
            .pnum = UINT64_C(0x0002000300010001),
            .idx  = 2,
            .lpv  = 0,
        },
        {
            /* 0xd(13):a==b,b!=c,c==d,d==e */
            .pnum = UINT64_C(0x0002000300010002),
            .idx  = 2,
            .lpv  = 1,
        },
        {
            /* 0xe(14):a!=b,b==c,c==d,d==e */
            .pnum = UINT64_C(0x0002000300040001),
            .idx  = 1,
            .lpv  = 0,
        },
        {
            /* 0xf(15):a==b,b==c,c==d,d==e */
            .pnum = UINT64_C(0x0002000300040005),
            .idx  = 0,
            .lpv  = 4,
        },
    };

    union {
        uint16_t u16[FWDSTEP+1];
        uint64_t u64;
    } *pnum = (void *)pn;

    int32_t v;
    dp1 = _mm_cmpeq_epi16(dp1, dp2);
    dp1 = _mm_unpacklo_epi16(dp1, dp1);
    v = _mm_movemask_ps((__m128)dp1);

    /* update last port number */
    lp[0] += gptbl[v].lpv;

    /* if dest port value has changed. */
    if (v != GRPMSK) {
        lp = pnum->u16 + gptbl[v].idx;
        lp[0] = 1;
        pnum->u64 = gptbl[v].pnum;
    }

    return lp;
}

#endif /* ENABLE_MULTI_BUFFER_OPTIMIZE == 1 */


/* init ipv4_l3fwd_route_array */
static void
init_ipv4_l3fwd_route_array()
{
    int i = 0;
    for (; i < m_config.num_of_routes; i++) {
        ipv4_l3fwd_route_array[i].ip = m_config.routes[i].ip;
        ipv4_l3fwd_route_array[i].depth = m_config.routes[i].prefix;
        ipv4_l3fwd_route_array[i].if_out = (uint8_t)m_config.routes[i].ifindex;
        ipv4_l3fwd_num_routes++;
    }
}

/* setup LPM */
static void
setup_lpm(int socket_id)
{
    unsigned i;
    int      ret;
    char     s[64];

    /* create the LPM table */
    snprintf(s, sizeof(s), "IPV4_L3FWD_LPM_%d", socket_id);
    ipv4_l3fwd_lookup_struct[socket_id] = rte_lpm_create(s, socket_id,
        IPV4_L3FWD_LPM_MAX_RULES, 0);
    if (ipv4_l3fwd_lookup_struct[socket_id] == NULL) {
        rte_exit(EXIT_FAILURE, 
            "Unable to create the l3fwd LPM table on socket %d\n", 
            socket_id);
    }

    /* populate the LPM table */
    for (i = 0; i < IPV4_L3FWD_LPM_MAX_RULES; i++) {
        /* skip unused ports */
        if ( ( (1 << ipv4_l3fwd_route_array[i].if_out) & 
            enabled_port_mask) == 0)
            continue;

        ret = rte_lpm_add(ipv4_l3fwd_lookup_struct[socket_id], 
            ipv4_l3fwd_route_array[i].ip,
            ipv4_l3fwd_route_array[i].depth,
            ipv4_l3fwd_route_array[i].if_out);

        if (ret < 0) {
            rte_exit(EXIT_FAILURE, "Unable to add entry %u to the "
                "l3fwd LPM table on socket %d\n", i, socket_id);
        }

        printf("LPM: Adding route 0x%08x / %d (%d)\n", 
            (unsigned)ipv4_l3fwd_route_array[i].ip,
            ipv4_l3fwd_route_array[i].depth, 
            ipv4_l3fwd_route_array[i].if_out);
    }
}

#endif /* end for LOOKUP_METHOD == LOOKUP_LPM */
