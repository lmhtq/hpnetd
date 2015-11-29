#include "stream.h"

char *tcp_state_str[] =
{
    "TCP_CLOSE",
    "TCP_ESTABLISHED",
    "TCP_SYN_SENT",
    "TCP_SYN_RECV",
    "TCP_FIN_WAIT1",
    "TCP_FIN_WAIT2",
    "TCP_TIME_WAIT",
    "TCP_CLOSE_WAIT",
    "TCP_LAST_ACK",
    "TCP_LISTEN",
    "TCP_CLOSING",    /* Now a valid a state */

    "TCP_MAX_STATES"  /* Leave at the end! */
};

char *tcp_close_reason_str[] =
{
    "TCP_NOT_CLOSED",
    "TCP_ACTIVE_CLOSE",
    "TCP_PASSIVE_CLOSE",
    "TCP_CONN_FAIL",
    "TCP_CONN_LOST",
    "TCP_RESET",
    "TCP_NO_MEM",
    "TCP_NOT_ACCEPTED",
    "TCP_TIMEOUT"
};

#if 1
/* basic stream function */
/* create tcp stream */
tcp_stream_t
create_tcp_stream(mmutcpd_manager_t mmt, socket_map_t sk, int type, 
    uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport)
{
    tcp_stream_t stream = NULL;
    int          ret;
    uint8_t      *sa;
    uint8_t      *da;

    /* TODO: flow_pool_lock */
    pthread_mutex_lock(&mmt->ctx->flow_pool_lock);
    /* TODO: MP_allocate_chunk */
    stream = (tcp_stream_t)MP_allocate_chunk(mmt->flow_pool);
    if (!stream) {
        fprintf(stderr, 
            "cannot allocate memory for the stream."
            "max_concurrency:%d, con_current:%d\n", 
            m_config.max_concurrency, mmt->flow_cnt);
        pthread_mutex_unlock(&mmt->ctx->flow_pool_lock);
        return NULL;
    }
    memset(stream, 0, sizeof(struct tcp_stream));

    stream->rcv_var = (tcp_recv_vars_t)MP_allocate_chunk(mmt->recv_vars_pool);
    if (!stream->rcv_var) {
        MP_free_chunk(mmt->flow_pool, stream);
        pthread_mutex_unlock(&mmt->ctx->flow_pool_lock);
        return NULL;
    }
    stream->snd_var = (tcp_send_vars_t)MP_allocate_chunk(mmt->send_vars_pool);
    if (!stream->snd_var) {
        MP_free_chunk(mmt->recv_vars_pool, stream->rcv_var);
        MP_free_chunk(mmt->flow_pool, stream);
        pthread_mutex_unlock(&mmt->ctx->flow_pool_lock);
        return NULL;
    }
    memset(stream->rcv_var, 0, sizeof(struct tcp_recv_vars));
    memset(stream->snd_var, 0, sizeof(struct tcp_send_vars));

    stream->id = mmt->g_id++;
    stream->saddr = saddr;
    stream->sport = sport;
    stream->daddr = daddr;
    stream->dport = dport;

    ret = insert_tcp_flow_hashtable(mmt->tcp_flow_hstable, stream);
    if (ret < 0) {
        fprintf(stderr, "Stream %d: Failed to insert "
            "the stream into hash table.\n", stream->id);
        MP_free_chunk(mmt->flow_pool, stream);
        pthread_mutex_unlock(&mmt->flow_pool_lock);
        return NULL;
    }
    stream->on_hash_table = TRUE;
    mmt->flow_cnt++;

    pthread_mutex_unlock(&mmt->ctx->flow_pool_lock);

    if (sk) {
        stream->sk = sk;
        sk->stream = stream;
    }

    stream->stream_type = type;
    stream->state = TCP_LISTEN;
    stream->on_rto_idx = -1;
    /* send/recv vars change */
    stream->snd_var->ip_id = 0;
    stream->snd_var->mss = TCP_DEFAULT_MSS;
    stream->snd_var->wscale = TCP_DEFAULT_WSCALE;
    /* TODO: the hardware out port */
    stream->snd_var->nif_out = get_out_port_id(stream->daddr);
    stream->snd_var->iss = rand() % TCP_MAXSEQ;
    stream->rcv_var->iss = 0;

    stream->snd_nxt = stream->snd_var->iss;
    stream->snd_var->snd_una = stream->snd_var->iss;
    stream->snd_var->snd_wnd = m_config.send_buf_size;
    stream->rcv_nxt = 0;
    stream->rcv_var->rcv_wnd = TCP_INIT_WINDOW;

    stream->rcv_var->snd_wl1 = stream->rcv_var->irs - 1;
    stream->rcv_var->rto = TCP_INIT_RTO;

    /* use spin lock */
    if (pthread_spin_init(&stream->rcv_var->read_lock, 
        PTHREAD_PROCESS_PRIVATE)) {
        perror("pthread_spin_init of read_lock");
        return NULL;
    }

    if (pthread_spin_init(&stream->rcv_var->write_lock, 
        PTHREAD_PROCESS_PRIVATE)) {
        perror("pthread_spin_init of write_lock");
        return NULL;
    }

    sa = (uint8_t *)&stream->saddr;
    da = (uint8_t *)&stream->daddr;
    fprintf(stderr, "create new tcp stream %d, %u.%u.%u.%u(%d) -> "
        "%u.%u.%u.%u(%d) (ISS:%u)\n", stream->id, sa[0], sa[1], sa[2], sa[3],
        ntohs(stream->sport), da[0], da[1], da[2], da[3], ntohs(stream->dport),
        stream->snd_var->iss);

    return stream;
}

/* destroy the tcp stream */
void 
destroy_tcp_stream(mmutcpd_manager_t mmt, tcp_stream_t stream)
{
    struct  sockaddr_in addr;
    int     bound_addr = FALSE;
    uint8_t *sa;
    uint8_t *da;
    int     ret;

    sa = (uint8_t *)&stream->saddr;
    da = (uint8_t *)&stream->daddr; 
    fprintf(stderr, "destroy tcp stream %d, %u.%u.%u.%u(%d) -> "
        "%u.%u.%u.%u(%d) (close_reason:%s)\n", stream->id, 
        sa[0], sa[1], sa[2], sa[3], ntohs(stream->sport), 
        da[0], da[1], da[2], da[3], ntohs(stream->dport),
        tcp_close_reason_str[stream->close_reason]);
    if (stream->snd_var->sndbuf) {
        fprintf(stderr, "stream %d: send buffer, cum_len:%lu, len:%u\n", 
            stream->snd_var->sndbuf->cum_len, stream->snd_var->sndbuf->len);
    }
    if (stream->rcv_var->rcvbuf) {
        fprintf(stderr, "stream %d: recv buffer, cum_len:%lu, "
            "merged_len:%u, last_len:%u\n", 
            stream->rcv_var->rcvbuf->cum_len, 
            stream->rcv_var->rcvbuf->merged_len, 
            stream->rcv_var->rcvbuf->last_len;
    }

    /* TODO: what it is */
    if (stream->is_bound_addr) {
        bound_addr = TRUE;
        addr.sin_addr.s_addr = stream->saddr;
        addr.sin_port = stream->sport;
    }

    remove_from_control_list(mmt, stream);
    remove_from_send_list(mmt, stream);
    remove_from_ack_list(mmt, stream);

    if (stream->on_rto_idx >= 0) {
        remove_from_rto_list(mmt, stream);
    }

    if (stream->on_timewait_list) {
        remove_from_timewait_list(mmt, stream);
    }

    if (m_config.max_concurrency > 0) {
        remove_from_timeout_list(mmt, stream);
    }

    /* destroy the read/write lock */
    pthread_spin_destroy(&stream->rcv_var->read_lock);
    pthread_spin_destroy(&stream->snd_var->write_lock);

    assert(stream->on_hash_table == TRUE);

    /* free ring buffers  */
    if (stream->snd_var->sndbuf) {
        /* TODO: sb free */
        sb_free(mmt->rbm_snd, stream->snd_var->sndbuf);
        stream->snd_var->sndbuf = NULL;
    }
    if (stream->rcv_var->rcvbuf) {
        /* TODO: sb free */
        sb_free(mmt->rbm_rcv, stream->rcv_var->rcvbuf);
        stream->rcv_var->rcvbuf = NULL;
    }

    pthread_mutex_lock(&mmt->ctx->flow_pool_lock);

    /* remove from flow hash table */
    remove_tcp_flow_hashtable(mmt->tcp_flow_hstable, stream);
    stream->on_hash_table = FALSE;

    mmt->flow_cnt--;

    MP_free_chunk(mmt->recv_vars_pool, stream->rcv_var);
    MP_free_chunk(mmt->send_vars_pool, stream->snd_var);
    MP_free_chunk(mmt->flow_pool, stream);
    pthread_mutex_unlock(&mmt->ctx->flow_pool_lock);

    if (bound_addr) {
        if (mmt->ap) {
            ret = fetch_address(mmt->ap, &addr);
        } else {
            ret = fetch_address(mmt->ap, &addr);
        }
        if (ret < 0) {
            fprintf(stderr, "Failed to free address.\n");
        }
    }

}

/* dump stream */
void 
dump_stream(mmutcpd_manager_t mmt, tcp_stream_t stream)
{
    uint8_t *sa;
    uint8_t *da;
    tcp_send_vars_t snd_var = stream->snd_var;
    tcp_recv_vars_t rcv_var = stream->rcv_var;
    /* TODO: in debug */
}
#endif /* basic stream function */

/* create a tcp_flow_hashtable */
tcp_flow_hashtable_t 
create_tcp_flow_hashtable()
{
    int i;
    tcp_flow_hashtable_t ht;
    ht = calloc(1, sizeof(struct tcp_flow_hashtable));
    if (!ht) {
        fprintf(stderr, "ht calloc failed," 
            " create_tcp_flow_hashtable\n");
        return 0;
    }

    /* init the tcp_flow_hashtable */
    for (i = 0; i < SHASH_ENTRY; i++) {
        TAILQ_INIT(&ht->ht_table[i]);
    }

    return ht;
}

/* hash of a tcp stream flow */
uint32_t
hash_of_stream(const tcp_stream_t item)
{
    /* BKDR hash */
    uint32_t hash = 0, i;
    uint32_t seed = 131;
    char *str = (char *)&item->saddr;

    for (i = 0; i < 12; i++) {
        hash = (hash * seed) + str[i];
    }
    hash &= 0x7fffffff;
    return (hash % SHASH_ENTRY);
}

/* two tcp_stream equal */
inline int 
stream_is_equal(const tcp_stream_t s1, const tcp_stream_t s2)
{
    return (s1->saddr == s2->saddr && 
        s1->sport == s2->sport && 
        s1->daddr == s2->daddr && 
        s1->dport == s2->dport)
}

/* destroy the tcp_flow_hashtable */
void 
destroy_tcp_flow_hashtable(tcp_flow_hashtable_t ht)
{
    /* TODO: destroy each entry */
    free(ht);
}

/* insert a tcp_stream into the tcp_flow_hashtable */
int 
insert_tcp_flow_hashtable(tcp_flow_hashtable_t ht, tcp_stream_t item)
{
    int idx;

    assert(ht);
    assert(ht->ht_count <= 655535);

    idx = hash_of_stream(item);
    assert(idx >= 0 && idx < SHASH_ENTRY);

    TAILQ_INSERT_TAIL(&ht->ht_table[idx], item, hash_entry_table_link);
    /* TODO: TCP_AR_CNT??? */
    item->ht_idx = 3;//TCP_AR_CNT;
    ht->ht_count++;

    return 0;
}

/* remove the tcp_stream from the tcp_flow_hashtable */
void*
remove_tcp_flow_hashtable(tcp_flow_hashtable_t, tcp_stream_t item)
{
    hash_bucket_head *head;
    int idx = hash_of_stream(item);

    head = &ht->ht_table[idx];
    TAILQ_REMOVE(head, item, hash_entry_table_link);
    ht->ht_count--;

    return item;
}

/* search the tcp_stream from the tcp_flow_hashtable */
tcp_stream_t
search_tcp_flow_hashtable(tcp_flow_hashtable_t ht, const tcp_stream_t item)
{
    int idx;
    tcp_stream_t itr;
    hash_bucket_head *head;

    idx = hash_of_stream(item);

    head = &ht->ht_table[idx];
    TAILQ_FOREACH(itr, head, rcv_var->hash_entry_table_link) {
        if (stream_is_equal(item, itr))
            return itr;
    }

    return NULL;
}

/* raise read event  */
inline void 
raise_read_event(mmutcpd_manager_t mmt, tcp_stream_t stream)
{
    if (stream->sk->epoll & EPOLL_IN) {
        add_epoll_event(mmt->ep. MMUTCPD_EVENT_QUEUE, 
            stream->sk, EPOLL_IN);
    } else {
        fprintf(stderr, 
            "Stream %d, raise read without a socket\n", stream->id);
    }
}

/* raise write event  */
inline void 
raise_write_event(mmutcpd_manager_t mmt, tcp_stream_t stream)
{
    if (stream->sk) {
        if (stream->sk->epoll & EPOLL_OUT) {
            add_epoll_event(mmt->ep, MMUTCPD_EVENT_QUEUE, 
                stream->sk, EPOLL_OUT);
        }
    } else {
        fprintf(stderr, 
            "Stream %d, raise write without a socket\n", stream->id);
    }
}

/* raise close event  */
inline void 
raise_close_event(mmutcpd_manager_t mmt, tcp_stream_t stream)
{
    if (stream->sk) {
        if (stream->sk->epoll & EPOLL_HUP) {
            add_epoll_event(mmt->ep, MMUTCPD_EVENT_QUEUE, 
                stream->sk, EPOLL_HUP);
        } else if (stream->sk->epoll & EPOLL_IN) {
            add_epoll_event(mmt->ep, MMUTCPD_EVENT_QUEUE, 
                stream->sk, EPOLL_IN);
        }
    } else {        
        fprintf(stderr, 
            "Stream %d, raise close without a socket\n", stream->id);
    }
}

/* raise error event  */
inline void 
raise_error_event(mmutcpd_manager_t mmt, tcp_stream_t stream)
{
    if (stream->sk) {
        if (stream->sk->epoll & EPOLL_ERR) {
            add_epoll_event(mmt->ep, MMUTCPD_EVENT_QUEUE, 
                stream->sk, EPOLL_ERR);
        }
    } else {        
        fprintf(stderr, 
            "Stream %d, raise error without a socket\n", stream->id);
    }

}
