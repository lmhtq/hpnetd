#include "tcp.h"

#if 1
/* tcp_out */
/* calcalute the length of the tcp option */
inline uint16_t 
/* TODO: need to be optimize!, or in a nicer way */
calc_opt_length(uint8_t flags)
{
    uint16_t optlen = 0;

    if (flags & TCP_FLAG_SYN) {
        optlen += TCP_OPT_MSS_LEN;
#if TCP_OPT_SACK_ENABLED
        optlen += TCP_OPT_SACK_PERMIT_LEN;
#if !TCP_OPT_TIMESTAMP_ENABLED
        optlen += 2;//for padding
#endif /* TCP_OPT_TIMESTAMP_ENABLED */
#endif /* TCP_OPT_SACK_ENABLED */

#if TCP_OPT_TIMESTAMP_ENABLED
        optlen += TCP_OPT_TIMESTAMP_LEN;
#if !TCP_OPT_SACK_ENABLED
        optlen += 2;//for padding
#endif /* TCP_OPT_SACK_ENABLED */
#endif /* TCP_OPT_TIMESTAMP_ENABLED */

        optlen += TCP_OPT_WSCALE_LEN + 1;
    } else {
#if TCP_OPT_TIMESTAMP_ENABLED
        optlen += TCP_OPT_TIMESTAMP_LEN + 2;
#endif /* TCP_OPT_TIMESTAMP_ENABLED */

#if TCP_OPT_SACK_ENABLED
        if (flags & TCP_FLAG_SACK) {
            optlen += TCP_OPT_SACK_LEN + 2;
        }
#endif /* TCP_OPT_SACK_ENABLED */
    }

    assert(optlen % 4 == 0);
}

/* generate tcp timestamp */
inline void 
generate_tcp_timestamp(tcp_stream_t cur, uint8_t *tcpopt, uint32_t cur_ts)
{
    uint32_t *ts = (uint32_t *)(tcpopt + 2);
    tcpopt[0] = TCP_OPT_TIMESTAMP;
    tcpopt[1] = TCP_OPT_TIMESTAMP_LEN;
    ts[0] = htonl(cur_ts);
    ts[1] = htonl(cur->rcv_var->ts_recent);
}

/* generate tcp options */
inline void
generate_tcp_option(tcp_stream_t cur, uint32_t cur_ts, uint8_t flags, 
    uint8_t *tcpopt, uint16_t optlen)
{
    int i = 0;

    if (flags & TCP_FLAG_SYN) {
        /* mss option */
        uint16_t mss;
        mss = cur->snd_var->mss;//init in create_tcp_stream
        tcpopt[i++] = TCP_OPT_MSS;
        tcpopt[i++] = TCP_OPT_MSS_LEN;
        tcpopt[i++] = mss >> 8;
        tcpopt[i++] = mss % 256;
    
        /* TODO: sack option */

        /* timestamp */
#if TCP_OPT_TIMESTAMP_ENABLED
#if !TCP_OPT_SACK_ENABLED
        tcpopt[i++] = TCP_OPT_NOP;
        tcpopt[i++] = TCP_OPT_NOP;
#endif /* TCP_OPT_SACK_ENABLED */
        generate_tcp_timestamp(cur, tcpopt + i, cur_ts);
        i += TCP_OPT_TIMESTAMP_LEN;
#endif /* TCP_OPT_TIMESTAMP_ENABLED */
        
        /* window scale */
        tcpopt[i++] = TCP_OPT_NOP;
        tcpopt[i++] = TCP_OPT_WSACLE;
        tcpopt[i++] = TCP_OPT_WSCALE_LEN;
        tcpopt[i++] = cur->snd_var->wscale;
    } else {
        /* TODO: sack */

        /* timestamp */
#if TCP_OPT_TIMESTAMP_ENABLED
        tcpopt[i++] = TCP_OPT_NOP;
        tcpopt[i++] = TCP_OPT_NOP;
        generate_tcp_timestamp(cur, tcpopt + i, cur_ts);
        i += TCP_OPT_TIMESTAMP_LEN;
#endif/* TCP_OPT_TIMESTAMP_ENABLED */

    }

    assert(i == optlen);
}

/* tcp checksum calc 
 * TODO: need to be optimised */
inline uint16_t
tcp_calc_check(*buf, uint16_t len, uint32_t saddr, uint32_t daddr)
{
    uint32_t sum;
    uint16_t *w;
    int nleft;

    sum = 0;
    nleft = len;
    w = buf;
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft) {
        sum += *w & ntohs(0xff00);
    }

    /* pseudo header */
    sum += (saddr & 0x0000ffff) + (saddr >> 16);
    sum += (daddr & 0x0000ffff) + (daddr >> 16);
    sum += htons(len);
    sum += htons(IPPROTO_TCP);

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    sum = ~sum;

    return (uint16_t)sum;
}

/* send tcp packet standalone */
int
send_tcp_packet_standalone(mmutcpd_manager_t mmt, 
    uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport, 
    uint32_t seq, uint32_t ack_seq, uint16_t window, uint8_t flags, 
    uint8_t *payload, uint16_t payloadlen,
    uint32_t cur_ts, uint32_t echo_ts)
{
    struct tcphdr *tcph;
    uint8_t       *tcpopt;
    uint32_t      *ts;
    uint16_t      optlen;

    optlen = calc_opt_length(flags);
    if (payloadlen > TCP_DEFAULT_MSS) {
        fprintf(stderr, "payloadlen size %u exceeds MSS\n", (uint32_t)payloadlen);
        assert(0);
        return ERROR;
    }

    /* TODO: */
    tcph = (struct tcphdr *)ip_outpout_standalone();
    if (!tcph) {
        return NULL;
    }
    
    memset(tcph, 0, TCP_HEADER_LEN + optlen);
    tcph->source = sport;
    tcph->dest = dport;
    if (flags & TCP_FLAG_SYN)
        tcph->syn = TRUE;
    if (flags & TCP_FLAG_FIN)
        tcph->fin = TRUE;
    if (flags & TCP_FLAG_RST)
        tcph->rst = TRUE;
    if (flags & TCP_FLAG_PSH)
        tcph->psh = TRUE;
    tcph->seq = htonl(seq);
    if (flags & TCP_FLAG_ACK) {
        tcph->ack = TRUE;
        tcph->ack_seq = htonl(ack_seq);
    }
    tcph->window = htons(MIN(window, TCP_MAX_WND));

    tcpopt = (uint8_t *)tcph + TCP_HEADER_LEN;
    ts = (uint32_t *)(tcpopt + 4);
    tcpopt[0] = TCP_OPT_NOP;
    tcpopt[1] = TCP_OPT_NOP;
    tcpopt[2] = TCP_OPT_TIMESTAMP;
    tcpopt[3] = TCP_OPT_TIMESTAMP_LEN;
    ts[0] = htonl(cur_ts);
    ts[1] = htonl(echo_ts);

    tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
    /* copy payload if exist */
    if (payloadlen > 0) {
        memcpy((uint8_t *)tcph + TCP_HEADER_LEN + optlen, payload, payloadlen);
    }
#if TCP_CALC_CHECKSUM
    tcph->check = tcp_calc_check((uint16_t *)tcph, 
        TCP_HEADER_LEN + optlen + payloadlen, saddr, daddr);
#endif /* TCP_CALC_CHECKSUM */

    if (tcph->syn || tcph->fin) {
        payloadlen++;
    }

    return payloadlen;
}

/* send tcp packet */
int 
send_tcp_packet(mmutcpd_manager_t mmt, tcp_stream_t cur, uint32_t cur_ts, 
    uint8_t flags, uint8_t *payload, uint16_t payloadlen)
{
    struct tcphdr *tcph;
    uint16_t      optlen;
    uint8_t       wscale = 0;
    uint32_t      window32 = 0;

    optlen = calc_opt_length(flags);
    if (payloadlen > cur->snd_var->mss) {
        fprintf(stderr, "payloadlen %u exceeds mss\n", (uint32_t)payloadlen);
    }

    tcph = (struct tcphdr*)ip_outpout_standalone();
    if (!tcph) {
        return -2;
    }
    memset(tcph, 0, TCP_HEADER_LEN, optlen);

    tcph->source = cur->sport;
    tcph->dest = cur->dport;

    if (flags & TCP_FLAG_SYN) {
        tcph->syn = TRUE;
        if (cur->snd_nxt != cur->snd_var->iss) {
            fprintf(stderr, "stream %d: weird SYN seq."
                "snd_nxt:%u, iss:%u\n", cur->id, 
                cur->snd_nxt, cur->snd_var->iss);
        }
    }

    if (flags & TCP_FLAG_RST) {
        tcph->rst = TRUE;
    }

    if (flags & TCP_FLAG_PSH) {
        tcph->psh = TRUE;
    }

    if (flags & TCP_FLAG_WACK) {
        tcph->seq = htonl(cur->snd_nxt - 1);
        fprintf(stderr, "stream %u: sending ack to get new window adv. "
            "seq:%u, peer_wnd:%u, snd_nxt - snd_una:%u\n", cur->id, 
            cur->snd_nxt-1, cur->snd_var->peer_wnd, 
            cur->snd_nxt - cur->snd_var->snd_una);
    } else if (flags & TCP_FLAG_FIN) {
        tcph->fin = TRUE;
        if (cur->snd_var->fss == 0) {
            fprintf(stderr, "stream %u: not fss set. closed:%u\n", 
                cur->id, cur->closed);
        }
        tcph->seq = htonl(cur->snd_var->fss);
        cur->snd_var->is_fin_sent = TRUE;
        fprintf(stderr, "stream %d, sending FIN. seq: %u, ack_seq:%u\n", 
            cur->id, cur->snd_nxt, cur->rcv_nxt);
    } else {
        tcph->seq = htonl(cur->snd_nxt);
    }

    if (flags & TCP_FLAG_ACK) {
        tcph->ack = TRUE;
        tcph->ack_seq = htonl(cur->rcv_nxt);
        cur->snd_var->ts_last_ack_snd = cur_ts;
        cur->last_active_ts = cur_ts;
        update_timeout_list(mmt, cur);
    }

    if (flags & TCP_FLAG_SYN) {
        wscale = 0;
    } else {
        wscale = cur->snd_var->wscale;
    }

    window32 = cur->rcv_var->rcv_wnd >> wscale;
    tcph->window = htons(MIN((uint16_t)window32, TCP_MAX_WND));
    /* if the advertised window is 0, we need to advertise again later */
    if (window32 == 0) {
        cur->need_wnd_adv = TRUE;
    }

    generate_tcp_option(cur, cur_ts, flags, 
        (uint8_t *)tcph + TCP_HEADER_LEN, optlen);

    tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
    /* copy payload if exist */
    if (payloadlen > 0) {
        memcpy((uint8_t *)tcph, TCP_HEADER_LEN + optlen, payload, payloadlen);
    }
#if TCP_CALC_CHECKSUM
    tcph->check = tcp_calc_check((uint16_t *)tcph, 
        TCP_HEADER_LEN + optlen + payloadlen, cur->saddr, cur->daddr);
#endif /* TCP_CALC_CHECKSUM */

    cur->snd_nxt += payloadlen;

    if (tcph->syn || tcph->fin) {
        cur->snd_nxt++;
        payloadlen++;
    }

    if (payloadlen > 0) {
        if (cur->state > TCP_ESTABLISHED) {
            fprintf(stderr, "payload after TCP_ESTABLISHED: length:%d,"
                " snd_nxt:%u\n", payloadlen, cur->snd_nxt);
        }
        /* update rto timer if have payload */
        cur->snd_var->ts_rto = cur_ts + cur->snd_var->rto;
        fprintf(stderr, "stream %u: updating rto timer. "
            "cur_ts:%u, rto %u, ts_rto: %u\n", cur->id, cur_ts, 
            cur->snd_var->rto, cur->snd_var->ts_rto);
        add_to_rto_list(mmt, cur);
    }

    return payloadlen;
}

/* flush tcp sending buffer: a core (send data) function
 * this function is to send the whole sending buffer 
 * by calls the send_tcp_packet() many times until the 
 * whole buffer is sent */
int 
flush_tcp_sending_buffer(mmutcpd_manager_t mmt, 
    tcp_stream_t cur, uint32_t cur_ts)
{
    tcp_send_vars_t snd_var = cur->snd_var;
    uint32_t        maxlen = snd_var->mss - calc_opt_length(TCP_FLAG_ACK);
    uint8_t         *data;
    uint32_t        buffered_len;
    uint32_t        seq;
    uint16_t        len;
    int16_t         sndlen;
    uint32_t        window;
    int             packets = 0;

    if (!snd_var->sndbuf) {
        fprintf(stderr, "Stream %d: No sending buffer avaliable.\n", cur->id);
        assert(0);
        return 0;
    }

    pthread_spin_lock(&snd_var->write_lock);

    if (snd_var->sndbuf->len == 0) {
        packets = 0;
        pthread_spin_unlock(&snd_var->write_lock);
        return packets;
    } 

    window = MIN(snd_var->cwnd, snd_var->peer_wnd);
    while (1) {
        seq = cur->snd_nxt;
        if (TCP_SEQ_LT(seq, snd_var->sndbuf->head_seq)) {
            fprintf(stderr, "Stream %d: invalid seq to send. "
                "state:%s, seq:%u, head_seq:%u.\n", cur->id, 
                tcp_state_str[cur->state], seq, snd_var->sndbuf->head_seq);
            assert(0);
            break;
        }
        buffered_len = snd_var->sndbuf->head_seq + snd_var->sndbuf->len - seq;
        if (cur->state > TCP_ESTABLISHED) {
            fprintf(stderr, "head_seq:%u, seq:%u, buffered_len:%u\n", 
                snd_var->sndbuf->head_seq, snd_var->sndbuf->len, buffered_len);
        }
        if (buffered_len == 0) {
            break;
        }

        data = snd_var->sndbuf->head + (seq - snd_var->sndbuf->head_seq);

        len = MIN(buffered_len, maxlen);
        if (len <= 0) {
            break;
        }

        if (cur->state > TCP_ESTABLISHED) {
            fprintf(stderr, "Flushing after TCP_ESTABLISHED:seq:%u, len:%u, "
                "buffered_len:%u\n", seq, len, buffered_len);
        }

        if (seq - snd_var->snd_una + len > window) {
            /* ask for new window advertisement to peer */
            if (seq - snd_var->snd_una + len > snd_var->peer_wnd) {
                if (TS_TO_MSEC(cur_ts - snd_var->ts_last_ack_snd) > 
                    TCP_TIMEOUT_VAL) {
                        enqueue_ack(mmt, cur, cur_ts, ACK_OPT_WACK);
                }
                packets = -3;
                pthread_spin_unlock(&snd_var->write_lock);
                return packets;
            }
        }

        sndlen = send_tcp_packet(mmt, cur, cur_ts, TCP_FLAG_ACK, data, len);
        if (sndlen < 0) {
            packets = sndlen;
            pthread_spin_unlock(&snd_var->write_lock);
            return packets;
        }
        packets++;
    }

    return packets;
}

/* send control packet: a core function
 * the tcp state machine */
inline int 
send_control_packet(mmutcpd_manager_t mmt, tcp_stream_t cur, uint32_t cur_ts)
{
    tcp_send_vars_t snd_var = cur->snd_var;
    int             ret = 0;

    switch (cur->state) {
        case TCP_SYN_SENT://send syn packet here
            ret = send_tcp_packet(mmt, cur, cur_ts, TCP_FLAG_SYN, NULL, 0);
            break;

        case TCP_SYN_RECV://send syn/ack packet here
            cur->snd_nxt = snd_var->iss;
            ret = send_tcp_packet(mmt, cur, cur_ts, 
                TCP_FLAG_SYN|TCP_FLAG_ACK, NULL, 0);
            break;

        case TCP_ESTABLISHED://send ack here
            ret = send_tcp_packet(mmt, cur, cur_ts, TCP_FLAG_ACK, NULL, 0);
            break;

        case TCP_CLOSE_WAIT://send ack for the fin
            ret = send_tcp_packet(mmt, cur, cur_ts, TCP_FLAG_ACK, NULL, 0);
            break;

        case TCP_LAST_ACK:
            //if it is on ack list, send it after sending ack
            if (snd_var->on_send_list || snd_var->on_ack_list) {
                ret = -1;
            }  else {//send fin/ack here
                ret = send_tcp_packet(mmt, cur, cur_ts, 
                    TCP_FLAG_FIN|TCP_FLAG_ACK, NULL, 0);
            }
            break;

        case TCP_FIN_WAIT1:
            //if it is on ack list, send it after sending ack
            if (snd_var->on_send_list || snd_var->on_ack_list) {
                ret = -1;
            }  else {//send fin/ack here
                ret = send_tcp_packet(mmt, cur, cur_ts, 
                    TCP_FLAG_FIN|TCP_FLAG_ACK, NULL, 0);
            }
            break;

        case TCP_FIN_WAIT2://send ack here
            ret = send_tcp_packet(mmt, cur, cur_ts, TCP_FLAG_ACK, NULL, 0);
            break;

        case TCP_CLOSING:
            if (snd_var->is_fin_sent) {
                /* if the seq is for FIN, send FIN */
                if (cur->snd_nxt == snd_var->fss) {/* TODO: FIN seq?? */
                    ret = send_tcp_packet(mmt, cur, cur_ts, 
                        TCP_FLAG_ACK|TCP_FLAG_FIN, NULL, 0);
                } else {
                    ret = send_tcp_packet(mmt, cur, cur_ts, TCP_FLAG_ACK, 
                        NULL, 0);
                }
            } else {
                /* if FIN is not sent, send FIN with ack */
                ret = send_tcp_packet(mmt, cur, cur_ts, 
                    TCP_FLAG_FIN|TCP_FLAG_ACK, NULL, 0);
            }
            break;

        case TCP_TIME_WAIT://send ack here
            ret = send_tcp_packet(mmt, cur, cur_ts, TCP_FLAG_ACK, NULL, 0);
            break;

        case TCP_CLOSE://closed, send RST here
            fprintf(stderr, "stream %d: try sending RST.\n", cur->id);
            /* first flush the data and ack */
            if (snd_var->on_send_list || snd_var->on_ack_list) {
                ret = -1;
            } else {
                ret = send_tcp_packet(mmt, cur, cur_ts, TCP_FLAG_RST, NULL, 0);
                if (ret >= 0) {
                    destroy_tcp_stream(mmt, cur);
                }
            }
            break;

        case default:
            ret = -1;
            break;
    }

    return ret;
}

/* write tcp control list 
 * traverse the control list */
/* TODO: the logic need to be optimized */
inline int 
write_tcp_control_list(mmutcpd_manager_t mmt, mmutcpd_sender_t *sender, 
    uint32_t cur_ts, int thresh)
{
    tcp_stream_t cur;
    tcp_stream_t next;
    tcp_stream_t last;
    int          cnt = 0;
    int          ret;

    thresh = MIN(thresh, sender->control_list_cnt);
    /* send tcp control msg */
    cnt = 0;
    cur = TAILQ_FIRST(&sender->control_list);
    last = TAILQ_LAST(&sender->control_list, control_head);
    while (cur) {
        if (++cnt > thresh) {
            break;
        }

        fprintf(stderr, "Inside control loop. cnt:%u, stream:%d\n", 
            cnt, cur->id);
        next = TAILQ_NEXT(cur, snd_var->control_link);

        if (cur->snd_var->on_control_list) {
            cur->snd_var->on_control_list = FALSE;
            ret = send_control_packet(mmt, cur, cur_ts);
            if (ret < 0) {
                /*failed, insert into the head and wait for the next loop */
                TAILQ_INSERT_HEAD(&sender->control_list, cur, 
                    snd_var->control_link);
                cur->snd_var->on_control_list = TRUE;
                sender->control_list_cnt++;
                break;
            }
        } else {
            fprintf(stderr, "stream %d: on_control_list is FALSE, but it is "
                "on the control list.\n", cur->id);
        }

        if (cur == last) {
            break;
        }
        cur = next;
    }

    return cnt;

}

/* write tcp data list */
inline int 
write_tcp_data_list(mmutcpd_manager_t mmt, mmutcpd_sender_t *sender, 
    uint32_t cur_ts, int thresh)
{
    tcp_stream_t cur;
    tcp_stream_t next;
    tcp_stream_t last;
    int          cnt = 0;
    int          ret;

    /* send data */
    cur = TAILQ_FIRST(&sender->send_list);
    last = TAILQ_LAST(&sender->send_list, send_head);
    while (cur) {
        if (++cnt > thresh) {
            break;
        }

        fprintf(stderr, "Inside data loop. cnt:%u, stream:%d\n", 
            cnt, cur->id);
        next = TAILQ_NEXT(&sender->list, cur, snd_var->send_link);
        TAILQ_REMOVE()
        if (cur->snd_var->on_send_list) {
            ret = 0;
            /* send data here. only when the state is 
             * ESTABLISEDH or CLOSE_WAIT */
            if (cur->state == TCP_ESTABLISHED) {
                if (cur->snd_var->on_control_list) {
                    ret = -1;
                } else {
                    ret = flush_tcp_sending_buffer(mmt, cur, cur_ts);
                }
            } else if (cur->state == TCP_CLOSE_WAIT || 
                cur->state == TCP_FIN_WAIT1 || 
                cur->state == TCP_LAST_ACK) {
                ret = flush_tcp_sending_buffer(mmt, cur, cur_ts);
            } else {
                fprintf(stderr, "stream %d:can't send data, in state %s\n", 
                    cur->id, tcp_state_str[cur->state]);
            }

            if (ret < 0) {
                TAILQ_INSERT_TAIL(&sender->send_list, cur, snd_var->send_link);
                /* no write buffer */
                break;
            } else {
                cur->snd_var->on_send_list = FALSE;
                sender->send_list_cnt--;
                /* the ret value is the number of packets sent,
                 * decrease ack_cnt for the piggybacked acks */
#if ACK_PIGGYBACK
                if (cur->snd_var->ack_cnt > 0) {
                    if (cur->snd_var->ack_cnt > ret ) {
                        cur->snd_var->ack_cnt -= ret;
                    } else {
                        cur->snd_var->ack_cnt = 0;
                    }
                }
#endif/* ACK_PIGGYBACK*/
                /* TODO: what is the: control_list_waiting */
                if (cur->control_list_waiting) {
                    if (!cur->on_ack_list) {
                        cur->control_list_waiting = FALSE;
                        add_to_control_list(mmt, cur, cur_ts);
                    }
                }
            }
        } else {
            fprintf(stderr, "stream %d: not on send list\n", cur->id);
        }

        if (cur == last) {
            break;
        }

        cur = next;
    }

    return cnt;
}

/* write tcp ack list */
inline int 
write_tcp_ack_list(mmutcpd_manager_t mmt, mmutcpd_sender_t *sender, 
    uint32_t cur_ts, int thresh)
{
    tcp_stream_t cur;
    tcp_stream_t next;
    tcp_stream_t last;
    int          to_ack;
    int          cnt = 0;
    int          ret;

    /* send aggregated acks */
    cnt = 0;
    cur = TAILQ_FIRST(&sender->ack_list);
    last = TAILQ_LAST(&sender->ack_list, ack_head);

    while (cur) {
        if (++cnt > thresh) {
            break;
        }

        fprintf(stderr, "stream %d: inside the ack loop\n", cur->id);
        next = TAILQ_NEXT(cur, snd_var->ack_link);
        if (cur->snd_var->on_ack_list) {
            /* this list is only ack the data packets
             * if the ack is not data ack, then it will not process here */
            to_ack = FALSE;
            if (cur->state == TCP_ESTABLISHED ||
                cur->state == TCP_CLOSE_WAIT ||
                cur->state == TCP_FIN_WAIT1 ||
                cur->state == TCP_FIN_WAIT2 ||
                cur->state == TCP_TIME_WAIT) {
                /* TIMEWAIT is possible since the ack is queued at FIN_WAIT2 */
                if (cur->rcv_var->rcvbuf) {
                    if (TCP_SEQ_LEQ(cur->rcv_nxt, 
                        cur->rcv_var->rcvbuf->head_seq + 
                        cur->rcv_var->rcvbuf->merged_len)) {
                        to_ack = TRUE;
                    }
                } 
            } else {
                fprintf(stderr, "stream %d(%s): try sending ack at "
                    "wrong state. seq:%u, ack_seq:%u, "
                    "on_control_list:%u\n", cur->id, 
                    tcp_state_str[cur->state], cur->snd_nxt, 
                    cur->rcv_nxt, cur->snd_var->on_control_list);
            }

            if (to_ack) {
                /* send the queued ack packets */
                while (cur->snd_var->ack_cnt > 0) {
                    ret = send_tcp_packet(mmt, cur, cur_ts, 
                        TCP_FLAG_ACK, NULL, 0);
                    if (ret < 0) {
                        /* since  there is no available 
                         * write buffer, break */
                        break;
                    }
                    cur->snd_var->ack_cnt--;
                }
                /* if is_wack is set, send packet to get 
                 * window advertisement */
                if (cur->snd_var->is_wack) {
                    cur->snd_var->is_wack = FALSE;
                    ret = send_tcp_packet(mmt, cur, cur_ts, 
                        TCP_FLAG_ACK | TCP_FLAG_WACK, NULL, 0);
                    if (ret < 0) {
                        /* no available write buffer, break */
                        cur->snd_var->is_wack = TRUE;
                    }
                }
                if (!(cur->snd_var->ack_cnt || cur->snd_var->is_wack) ) {
                    cur->snd_var->on_ack_list = FALSE;
                    TAILQ_REMOVE(&sender->ack_list, cur, 
                        snd_var->ack_link);
                    sender->ack_list_cnt--;
                }
            } else {
                cur->snd_var->on_ack_list = FALSE;
                cur->snd_var->ack_cnt = 0;
                cur->snd_var>is_wack = 0;
                TAILQ_REMOVE(&sender->ack_list, cur, snd_var->ack_link);
                sender->ack_list_cnt---;
            }
            
            if (cur->control_list_waiting) {
                if (!cur->snd_var->on_send_list) {
                    cur->control_list_waiting = FALSE;
                    add_to_control_list(mmt, cur, cur_ts);
                }
            }
        } else {
            fprintf(stderr, "stream %d: not on ack_list.\n", cur->id);
            TAILQ_REMOVE(&sender->ack_list, cur, snd_var->ack_link);
            sender->ack_list_cnt--;
        }

        if (cur == last) {
            break;
        }
        cur = next;
    }

    return cnt;
}

/* get sender */
inline mmutcpd_sender_t
get_sender(mmutcpd_manager_t mmt, tcp_stream_t cur)
{
    int8_t           nif_out = cur->snd_var->nif_out;
    if (nif_out < 0 || nif_out >= m_config.num_of_nics) {
        return mmt->g_sender;
    } else {
        return mmt->n_sender[nif_out];
    }
}

/* add to control list */
inline void 
add_to_control_list(mmutcpd_manager_t mmt, tcp_stream_t cur)
{
    mmutcpd_sender_t sender = get_sender(mmt, cur);
    if (!cur->snd_var->on_control_list) {
        cur->snd_var->on_control_list = TRUE;
        TAILQ_INSERT_TAIL(&sender->control_list, cur, snd_var->control_link);
        sender->control_list_cnt++;
    }
}

/* add to send list */
inline void
add_to_send_list(mmutcpd_manager_t mmt, tcp_stream_t cur)
{
    mmutcpd_sender_t sender = get_sender(mmt, cur);
    if (!cur->snd_var->on_send_list) {
        cur->snd_var->on_send_list = TRUE;
        TAILQ_INSERT_TAIL(&sender->send_list, cur, snd_var->send_link);
        sender->send_list_cnt++;
    }
}

/* add to ack list */
inline void 
add_to_ack_list(mmutcpd_manager_t mmt, tcp_stream_t cur)
{
    mmutcpd_sender_t sender = get_sender(mmt, cur);
    if (!cur->snd_var->on_send_list) {
        cur->snd_var->on_send_list = TRUE;
        TAILQ_INSERT_TAIL(&sender->ack_list, cur, snd_var->ack_link);
        sender->ack_list_cnt++;
    }
}


/* enqueue ack, this maybe a import position to change */
inline void 
enqueue_ack(mmutcpd_manager_t mmt, tcp_stream_t cur, 
    uint32_t cur_ts, uint8_t opt)
{
    fprintf(stderr, "stream %d(%s): enqueueing ack\n", 
        cur->id, cur->state);
    if (opt == ACK_OPT_NOW) {
        cur->snd_var->ack_cnt++;
    } else if (opt == ACK_OPT_AGGREGATE) {
        if (cur->snd_var->ack_cnt == 0) {
            cur->snd_var->ack_cnt = 1;
        }
    } else if (opt == ACK_OPT_WACK) {
        cur->snd_var->is_wack = TRUE;
    }
    add_to_ack_list(mmt, cur);
}
#endif /* tcp_out */

#if 1
/* tcp_in */
/* filter SYN packet */
inline int 
filter_syn_packet(mmutcpd_manager_t mmt, uint32_t ip, uint16_t port)
{
    struct sockaddr_in *addr;
    /* TODO: this listening logic should be revised */

    /* if not listening, drop */
    if (!mmt->listener) {
        /* TODO: check where it is set */
        return FALSE;
    }

    /* if not the address we want, drop */
    addr = &mmt->listener->sk->saddr;
    if (addr->sin_port == port) {
        if (addr->sin_addr.s_addr != INADDR_ANY) {
            if (ip == addr->sin_addr.s_addr) {
                return TRUE;
            } 
            return FALSE;
        } else {
            int i;
            for (i = 0; i < m_config.num_of_nics; i++) {
                if (ip == m_config.nics[i].ip_addr) {
                    return TRUE;
                }
            }
            return FALSE;
        }
    }

    return FALSE;
}


/* parse tcp options, mainly used in receive side */
inline void 
parse_tcp_options(mmutcpd_manager_t mmt, uint32_t cur_ts, 
    uint8_t *tcpopt, int len)
{
    int      i;
    uint32_t opt, optlen;
    /* TODO: should be revised */
    for (i = 0; i < len; ) {
        opt = *(tcpopt + i++);

        if (opt == TCP_OPT_END) {//end of option field
            break;
        } else if (opt == TCP_OPT_NOP) {//for padding
            continue;
        } else {
            optlen = *(tcpopt + i++);
            if (i + optlen - 2 > len) {
                break;
            }

            if (opt == TCP_OPT_MSS) {
                cur->snd_var->mss = *(tcpopt + i++) << 8;
                cur->snd_var->mss += *(tcpopt + i++);
                cur->snd_var->eff_mss = cur->snd_var->mss;
#if TCP_OPT_TIMESTAMP_ENABLED
                cur->snd_var->eff_mss -= (TCP_OPT_TIMESTAMP_LEN + 2);/* ??? */
#endif /* TCP_OPT_TIMESTAMP_ENABLED */
            } else if (opt == TCP_OPT_WSACLE) {
                cur->snd_var->wscale = *(tcpopt + i++);
            } else if (opt == TCP_OPT_SACK_PERMIT) {
                cur->sack_permit = TRUE;
                fprintf(stderr, "saw remote sack permit.\n");
            } else if (opt == TCP_OPT_TIMESTAMP) {
                cur->saw_timestamp = TRUE;
                cur->rcv_var->ts_recent = ntohl( *(uint32_t *)(tcpopt + i) );
                cur->rcv_var->ts_last_ts_upd = cur_ts;
                i += 8;
            } else {
                /* not handle */
                i += (optlen - 2);
            }
        }
    } 
}

/* handle passive open */
inline tcp_stream_t 
handle_passive_open(mmutcpd_manager_t mmt, uint32_t cur_ts, 
    const struct iphdr *iph, const struct tcphdr *tcph, uint32_t seq, 
    uint16_t window)
{
    tcp_stream_t cur = NULL;
    /* create new stream and add to the tcp hash flow table */
    cur = create_tcp_stream(mmt, NULL, SOCK_STREAM, iph->daddr, tcph->dest, 
        iph->saddr,tcph->source);
    if (!cur) {
        fprintf(stderr, "cant allocate a tcp_stream\n");
        return FALSE;
    }
    /* init rcv vars */
    cur->rcv_var->irs = seq;
    cur->snd_var->peer_wnd = window;
    cur->rcv_nxt = seq;//cur->rcv_var->irs;
    cur->snd_var->cwnd = 1;
    parse_tcp_options(cur, cur_ts, (uint8_t*)tcph + TCP_HEADER_LEN, 
        (tcph->doff << 2) - TCP_HEADER_LEN);
    return cur;
}

/* handle active open */
inline tcp_stream_t 
handle_active_open(mmutcpd_manager_t mmt, tcp_stream_t cur, uint32_t cur_ts, 
    struct tcphdr *tcph, uint32_t seq, uint32_t ack_seq, uint16_t window)
{
    /* init rcv vars */
    cur->rcv_var->irs = seq;
    cur->snd_nxt = ack_seq;
    cur->snd_var->peer_wnd = window;
    cur->rcv_var->snd_wl1 = cur->rcv_var->irs -1;
    cur->rcv_nxt = cur->rcv_var->irs + 1;
    cur->rcv_var->last_ack_seq = ack_seq;
    parse_tcp_options(cur, cur_ts, (uint8_t *)tcph * TCP_HEADER_LEN, 
        (tcph->doff << 2) - TCP_HEADER_LEN);
    cur->snd_var->cwnd = ( (cur->snd_var->cwnd == 1) ? 
        (cur->snd_var->mss * 2) : (cur->snd_var->mss) );
    cur->snd_var->ssthresh = cur->snd_var->mss * 10;
    update_rto_timer(cur, cur_ts);

    return TRUE;
}

/* parse tcp timestamp */
inline int 
parse_tcp_timestamp(tcp_stream_t cur, tcp_timestamp_t ts, 
    uint8_t *tcpopt, int len)
{
    int      i;
    uint32_t opt, optlen;

    for (i = 0; i < len;) {
        opt = *(tcpopt + i++);
        if (opt == TCP_OPT_END) {
            break;
        } else if (opt == TCP_OPT_NOP) {
            continue;
        } else {
            optlen = *(tcph + i++);
            if (i + optlen - 2 > len) {
                break;
            }

            if (opt == TCP_OPT_TIMESTAMP) {
                ts->ts_val = ntohl(*(uint32_t *)(tcpopt + i));
                ts->ts_ref = ntohl(*(uint32_t *)(tcpopt + i + 4));
            } else {
                // not handle
                i += (optlen - 2);
            }
        }
    }

    return FALSE;
}

/* validate sequence */
/* return TRUE: the seq is right
   return FALSE: the seq is wrong */
inline int 
validate_sequence(mmutcpd_manager_t mmt, tcp_stream_t cur, uint32_t cur_ts, 
    struct tcphdr *tcph, uint32_t seq, uint32_t ack_seq, int payloadlen)
{
    /* PAWS: protect against wrapped sequence number */
    if (!tcph->rst && cur->saw_timestamp) {
        struct tcp_timestamp ts;

        if (!parse_tcp_timestamp(cur, &ts, (uint8_t *)tcph + TCP_HEADER_LEN, 
            (tcph->doff << 2) - TCP_HEADER_LEN)) {
            /* if there is no timestamp */
            fprintf(stderr, "No timestamp found.\n");
            return FALSE;
        } 

        /* RFC1323: if SEG.TSVal < TS.Recent, drop and send ack */
        if (TCP_SEQ_LT(ts.ts_val, cur->rcv_var->ts_recent)) {
            /* TODO: ts_recent should be invalidated before timestamp
             * wraparound for long idle flow */
            fprintf(stderr, "PAWS detect wrong timestamp. seq:%u, ts_val:%u, "
                "prev:%u\n", seq, ts.ts_val, cur->rcv_var->ts_recent);
            enqueue_ack(mmt, cur, cur_ts, ACK_OPT_NOW);
            return FALSE;
        } else {
            /* validate timestamp */
            if (TCP_SEQ_GT(ts.ts_val, cur->rcv_var->ts_recent)) {
                fprintf(stderr, "timestamp update. cur:%u, prior:%u "
                    "(time diff:%uus)\n", ts.ts_val, cur->rcv_var->ts_recent, 
                    TS_TO_USEC(cur_ts - cur->rcv_var->ts_last_ts_upd));
                cur->rcv_var->ts_last_ts_upd = cur_ts;
            }

            cur->rcv_var->ts_recent = ts.ts_val;
            cur->rcv_var->ts_last_ack_rcv = ts.ts_ref;
        }
    }

    /* tcp sequence validation */
    if (!TCP_SEQ_BT(seq + payloadlen, cur->rcv_nxt, 
        cur->rcv_nxt + cur->rcv_var->rcv_wnd - 1)) {

        /* if RST bit is set, ignore the segment */
        if (tcph->rst) {
            return FALSE;
        }

        if (cur->state == TCP_ESTABLISHED) {
            /* check if it is to get window advertisement */
            if (seq + 1 == cur->rcv_nxt) {
                enqueue_ack(mmt, cur, cur_ts, ACK_OPT_AGGREGATE);
                return FALSE;
            }

            if (TCP_SEQ_LEQ(seq, cur->rcv_nxt)) {
                enqueue_ack(mmt, cur, cur_ts, ACK_OPT_AGGREGATE);
            } else {
                enqueue_ack(mmt, cur, cur_ts, ACK_OPT_NOW);
            }
        } else {
            if (cur->state == TCP_TIME_WAIT) {
                add_to_timewait_list(mmt, cur, cur_ts);
            }
            add_to_control_list(mmt, cur, cur_ts);
        }
        return FALSE;
    }
    return TRUE;
}

/* notify signal "connection reset" to app */
inline void 
notify_conn_rest_to_app(mmutcpd_manager_t mmt, tcp_stream_t cur)
{
    /* TODO: signal to app */
    fprintf(stderr, "Stream %d: notifying connection reset to app\n", cur->id);
}

/* process RST packet */
inline int 
process_rst(mmutcpd_manager_t mmt, tcp_stream_t cur, uint32_t ack_seq)
{
    /* TODO: reset validateion logic */
    /* the seq of a RST should be in window (in SYN_SENT state, 
     * should ack the previous SYN) */
    fprintf(stderr, "stream %d(%s): tcp reset.\n", cur->id, 
        tcp_state_str[cur->state]);

    if (cur->state <= TCP_SYN_SENT) {
        /* not handle here */
        return FALSE;
    }

    if (cur->state == TCP_SYN_RECV) {
        if (ack_seq == cur->rcv_nxt) {
            cur->state = TCP_CLOSE;
            cur->close_reason = TCP_RESET;
            destroy_tcp_stream(mmt, cur);
        }
        return TRUE;
    }

    /* if the app is already  closed the conn, just destroy it */
    if (cur->state == TCP_FIN_WAIT1 || cur->state == TCP_FIN_WAIT2 || 
        cur->state == TCP_LAST_ACK || cur->state == TCP_CLOSING || 
        cur->state == TCP_TIME_WAIT) {
        cur->state = TCP_CLOSE;
        cur->close_reason = TCP_ACTIVE_CLOSE;
        destroy_tcp_stream(mmt, cur);
        return TRUE;
    }

    if (cur->state >= TCP_ESTABLISHED && cur->state <= TCP_TIME_WAIT) {
        /* ESTAB, FIN1, FIN2, CLOSE_WAIT */
        /* TODO: flush all the segment queues */
        //notify_conn_rest_to_app(mmt, cur);
    }

    if (!(cur->snd_var->on_closeq || cur->snd_var->on_closeq_int || 
        cur->snd_var->on_resetq || cur->snd_var->on_resetq_int)) {
        cur->state = TCP_CLOSE_WAIT;
        cur->close_reason = TCP_RESET;
        raise_close_event(mmt, cur);
    }

    return TRUE;
}

/* estimate the RTT value */
inline void 
estimate_rtt(mmutcpd_manager_t mmt, tcp_stream_t cur, uint32_t mrtt)
{
    /* be called by not retransmitted packets */
    /* TODO: determine tcp_rto_min */
#define TCP_RTO_MIN 0
    long     m = mrtt;
    uint32_t tcp_rto_min = TCP_RTO_MIN;
    tcp_recv_vars_t rcv_var = cur->rcv_var;

    if (m == 0) {
        m = 1;
    }

    if (rcv_var->srtt != 0) {
        /* rtt = 7/8 rtt + 1/8 new */ 
        m -= (rcv_var->srtt >> 3);
        rcv_var->srtt += m;
        if (m < 0) {
            m = -m;
            m -= (rcv_var->mdev >> 2);
            if (m > 0) {
                m >>= 3;/* ??? */
            }
        } else {
            m -= (rcv_var->mdev >> 2);
        }
        rcv_var->mdev += m;

        if (rcv_var->mdev > rcv_var->mdev_max) {
            rcv_var->mdev_max = rcv_var->mdev;
            if (rcv_var->mdev_max > rcv_var->rttvar) {
                rcv_var->rttvar = rcv_var->mdev_max;
            }
        }

        if (TCP_SEQ_GT(cur->snd_var->snd_una, rcv_var->rtt_seq)) {
            if (rcv_var->mdev_max < rcv_var->rttvar) {
                rcv_var->rttvar -= (rcv_var->rttvar - rcv_var->mdev_max) >> 2;
            }
            rcv_var->rtt_seq = cur->snd_nxt;
            rcv_var->mdev_max = tcp_rto_min;
        }
    } else {
        /* fresh measurement */
        rcv_var->srtt = m << 3;
        rcv_var->mdev = m << 1;
        rcv_var->mdev_max = rcv_var->rtttt = MAX(rcv_var->mdev, tcp_rto_min);
        rcv_var->rtt_seq = cur->snd_nxt;
    }

    fprintf(stderr, "mrtt:%u(%uus), srtt:%u(%ums), mdev:%u, mdev_max:%u, "
        "rttvar:%u, rtt_seq:%u\n", mrtt, TS_TO_USEC(mrtt), rcv_var->srtt, 
        TS_TO_MSEC(rcv_var->srtt >> 3), rcv_var->mdev, rcv_var->mdev_max, 
        rcv_var->rttvar, rcv_var->rtt_seq);
}

/* process ACK packet */
inline void 
process_ack(mmutcpd_manager_t mmt, tcp_stream_t cur, uint32_t cur_ts, 
    struct tcphdr *tcph, uint32_t seq, uint32_t ack_seq, uint16_t window, 
    int payloadlen)
{
    tcp_send_vars_t snd_var = cur->snd_var;
    tcp_recv_vars_t rcv_var = cur->rcv_var;
    uint32_t        cwnd, cwnd_prev;
    uint32_t        rmlen;
    uint32_t        snd_wnd_prev;
    uint32_t        right_wnd_edge;
    uint8_t         dup;
    int             ret;

    cwnd = window;
    if (!tcph->syn) {
        cwnd = cwnd << snd_var->wscale;
    }
    right_wnd_edge = snd_var->peer_wnd + rcv_var->snd_wl2;

    /* if ack overs the sending buffer, return */
    if (cur->state == TCP_FIN_WAIT1 || cur->state == TCP_FIN_WAIT2 || 
        cur->state == TCP_CLOSING || cur->state == TCP_CLOSE_WAIT || 
        cur->state == TCP_LAST_ACK ) {
        if (snd_var->is_fin_sent && ack_seq == snd_var->sndbuf->len) {
            ack_seq--;
        }
    }

    if (TCP_SEQ_GT(ack_seq, snd_var->sndbuf->head_seq + snd_var->sndbuf->len)) {
        fprintf(stderr, "stream %d(%s): invalid ack. ack_seq:%u, "
            "possible max_ack_seq:%u\n", cur->id, tcp_state_str[cur->state], 
            ack_seq, snd_var->sndbuf->head_seq + snd_var->sndbuf->len);
        return ;
    }

    /* update window */
    if (TCP_SEQ_LEQ(rcv_var->snd_wl1, seq) && 
        TCP_SEQ_LEQ(rcv_var->snd_wl2, ack_seq)) {
        cwnd_prev = snd_var->peer_wnd;
        snd_var->peer_wnd = cwnd;
        rcv_var->snd_wl1 = seq;
        rcv_var->snd_wl2 = ack_seq;

        if (cwnd_prev < cur->snd_nxt - snd_var->snd_una && 
            snd_var->peer_wnd >= cur->snd_nxt - snd_var->snd_una) {
            fprintf(stderr, "stream %d:broadcasting client window update! "
                "ack_seq:%u, peer_wnd:%u(before:%u), (snd_nxt-snd_una:%u)\n", 
                cur->id, ack_seq, snd_var->peer_wnd, cwnd_prev, 
                cur->snd_nxt - snd_var->snd_una);
            raise_write_event(mmt, cur);
        }
    }

    /* check dup ack count */
    /* dup ack if 
     * 1. ack_seq is old
     * 2. payloadlen is 0
     * 3. advertised window not changed
     * 4. there is outstanding unacknowledged data
     * 5. ack_seq == snd_una */
    dup = FALSE;
    if (TCP_SEQ_LT(ack_seq, cur->snd_nxt) && 
        ack_seq == rcv_var->last_ack_seq && payloadlen == 0 && 
        rcv_var->snd_wl2 + snd_var->peer_wnd == right_wnd_edge) {
        rcv_var->dup_acks++;
        dup = TRUE;
    }
    if (!dup) {
        rcv_var->dup_acks = 0;
        rcv_var->last_ack_seq = ack_seq;
    }

    /* fast retransmission */
    if (dup && rcv_var->dup_acks == 3) {
        fprintf(stderr, "stream %d: Triple dup acks! ack_seq:%u\n", 
            cur->id, ack_seq);
        if (TCP_SEQ_LT(ack_seq, cur->snd_nxt)) {
            fprintf(stderr, "stream %d: reducing snd_nxt from %u to %u\n", 
                cur->id, cur->snd_nxt, ack_seq);
            if (ack_seq != snd_var->snd_una) {
                fprintf(stderr, "stream %d: ack_seq and snd_una mismatch on "
                    "triple dup acks.\n", cur->id, ack_seq, snd_var->snd_una);
            }
            cur->snd_nxt = ack_seq;
        }

        /* update congestion control variables */
        /* ssthresh to half of min of cwnd and peer_wnd */
        snd_var->ssthresh = MIN(snd_var->cwnd, snd_var->peer_wnd) >> 1;
        snd_var->ssthresh = MAX(snd_var->ssthresh, snd_var->mss << 1);
        snd_var->cwnd = snd_var->ssthresh + 3 * snd_var->mss;
        fprintf(stderr, "stream %d: fast retransmission. "
            "cwnd:%u, ssthresh:%u\n", cur->id, snd_var->cwnd, 
            snd_var->ssthresh);

        /* count number of retransmission */
        if (snd_var->nrtx < TCP_MAX_RTX) {
            snd_var->nrtx++;
        } else {
            fprintf(stderr, "stream %d: exceeds TCP_MAX_RTX\n", cur->id);
        }

        add_to_send_list(mmt, cur);
    } else if (rcv_var->dup_acks > 3) {
        /* inflate congestion window until before overflow */
        if ( (uint32_t)(snd_var->cwnd + snd_var->mss) > snd_var->cwnd ) {
            snd_var->cwnd += snd_var->mss;
            fprintf(stderr, "stream %d: dup ack cwnd inflate. cwnd:%u, "
                "ssthresh:%u\n", cur->id, snd_var->cwnd, snd_var->ssthresh);
        }
    }

#if TCP_OPT_SACK_ENABLED
    /* TODO: implement SACK */
    //parse_sack_option
#endif /* TCP_OPT_SACK_ENABLED */

#if RECOVERY_AFTER_LOSS
    /* updating snd_nxt (when recovered from loss) */
    if (TCP_SEQ_GT(ack_seq, cur->snd_nxt)) {
        fprintf(stderr, "stream %d:updating snd_nxt from %u to %u.\n", 
            cur->snd_nxt, ack_seq);
        cur->snd_nxt = ack_seq;
        if (snd_var->sndbuf->len == 0) {
            remove_from_send_list(mmt, cur);
        }
    }
#endif /* RECOVERY_AFTER_LOSS */
    
    /* if ack_seq is previous acked, return */
    if (TCP_SEQ_GEQ(snd_var->sndbuf->head_seq, ack_seq)) {
        return;
    }

    /* TODO: ??? remove acked sequence from send buffer */
    rmlen = ack_seq - snd_var->sndbuf->head_seq;
    if (rmlen > 0) {
        /* routine goes here only if there is new payload (not retransmitted) */
        uint16_t packets;
        
        /* if acks new data */
        packets = rmlen / snd_var->eff_mss;
        if ((rmlen / snd_var->eff_mss) * snd_var->eff_mss > rmlen ) {
            packets++;
        }

        /* estimate rtt and calc rto */
        if (cur->saw_timestamp) {
            estimate_rtt(mmt, cur, cur_ts - rcv_var->ts_last_ack_rcv);
            snd_var->rto = (rcv_var->srtt >> 3) + rcv_var->rttvar;
        } else {
            /* TODO: implement no timestamp estimate */

        }

        /* update congestion variables */
        if (cur->state >= TCP_ESTABLISHED) {
            if (snd_var->cwnd < snd_var->ssthresh) {
                if (snd_var->cwnd + snd_var->mss * packets > snd_var->cwnd) {
                    snd_var->cwnd += snd_var->mss * packets;
                }
                fprintf(stderr, "stream %d:slow start, cwnd:%u, ssthresh:%u\n", 
                    cur->id, snd_var->cwnd, snd_var->ssthresh);
            } else {
                uint32_t new_cwnd = snd_var->cwnd + packets * 
                snd_var->mss * snd_var->mss / snd_var->cwnd;
                if (new_cwnd > snd_var->cwnd) {
                    snd_var->cwnd = new_cwnd;
                }
                fprintf(stderr, "stream %d: congestion avoidance cwnd:%u, "
                    "ssthresh:%u\n", snd_var->cwnd, snd_var->ssthresh);
            }
        }

        if (pthread_spin_lock(&snd_var->write_lock)) {
            if (errno == EDEADLK) {
                fprintf(stderr, 
                    "stream %d:dead lock in process_ack\n", cur->id);
            }
            assert(0);
        }

        /* remove buffer */
        ret =sb_remove(mmt->rbm_snd, snd_var->sndbuf, rmlen);
        snd_var->snd_una = ack_seq;
        snd_wnd_prev = snd_var->snd_wnd;
        snd_var->snd_wnd = snd_var->sndbuf->size - snd_var->sndbuf->len;

        /* if there was no available sending window, 
         * notify newly avaliable window to app */
        raise_write_event(mmt, cur);

        pthread_spin_unlock(&snd_var->write_lock);

        update_rto_timer(mmt, cur, cur_ts);
    }

}

/* process tcp payload: merge tcp payload using receive ring buffer
 * return TRUE: in normal case
 * return FALSE: immediate ACK is required
 * NOTE: only can be called at ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2 */
inline int 
process_tcp_payload(mmutcpd_manager_t mmt, tcp_stream_t cur, uint32_t cur_ts, 
    uint8_t *payload, uint32_t seq, int payloadlen)
{
    tcp_recv_vars_t rcv_var = cur->rcv_var;
    tcp_send_vars_t snd_var = cur->snd_var;
    uint32_t        prev_rcv_nxt;
    int             ret;

    /* if seq and segment length is lower than rcv_nxt, ignore and send ack */
    if (TCP_SEQ_LT(seq + payloadlen, cur->rcv_nxt)) {
        return FALSE;
    }

    /* if payload exceeds receiving buffer, drop and send ack */
    if (TCP_SEQ_GT(seq + payloadlen, cur->rcv_nxt + rcv_var->rcv_wnd)) {
        return FALSE;
    }

    /* allocate reveive buffer if not exist */
    if (!rcv_var->rcvbuf) {
        rcv_var->rcvbuf = rb_init(mmt->rbm_rcv, rcv_var->irs + 1);
        if (!rcv_var->rcvbuf) {
            fprintf(stderr, 
                "stream %d: failed to allocate receive buffer.\n", cur->id);
            cur->state = TCP_CLOSE;
            cur->close_reason = TCP_NO_MEM;
            raise_error_event(mmt, cur);

            return ERROR;
        }
    }

    if (pthread_spin_lock(&rcv_var->read_lock)) {
        if (errno == EDEADLK) {
            fprintf(stderr, 
                "stream %d: dead lock in process_tcp_payload.\n", cur->id);
        }
        assert(0);    
    }

    prev_rcv_nxt = cur->rcv_nxt;
    ret = rb_put(mmt->rbm_rcv, rcv_var->rcvbuf, 
        payload, (uint32_t)payloadlen, seq);
    if (ret < 0) {
        fprintf(stderr, "stream %d:cant merge payload. reason:%d.\n", 
            cur->id, ret);

    }

    /* discard the buffer if the state is FIN_WAIT1|FIN_WAIT2, 
     * meaning that the connection is already closed by the app */
    if (cur->state == TCP_FIN_WAIT1 || cur->state == TCP_FIN_WAIT2) {
        rb_remove(mmt->rbm_rcv, rcv_var->rcvbuf, 
            rcv_var->rcvbuf->merged_len, AT_MMUTCPD);
    }
    cur->rcv_nxt = rcv_var->rcv_buf->head_seq + rcv_var->rcvbuf->merged_len;
    rcv_var->rcv_wnd = rcv_var->rcvbuf->size - 1 - rcv_var->rcv_buf->last_len;

    pthread_spin_unlock(&rcv_var->read_lock);

    if (TCP_SEQ_LEQ(cur->rcv_nxt, prev_rcv_nxt)) {
        /* there are some lost packets */
        return FALSE;
    }

    fprintf(stderr, "stream %d: data arrived. len:%d, ET:%u, IN:%u, OUT:%u\n", 
        cur->id, payloadlen, cur->sk ? cur->sk->epoll & EPOLL_ET : 0, 
        cur->sk ? cur->sk->epoll & EPOLL_IN : 0, 
        cur->sk ? cur->sk->epoll & EPOLL_OUT : 0);

    if (cur->state == TCP_ESTABLISHED) {
        raise_read_event(mmt, cur);
    }

    return TRUE;
}

/* create new flow hashtable entry */
inline tcp_stream_t 
create_new_flow_hashtable_entry(mmutcpd_manager_t mmt, uint32_t cur_ts, 
    const struct iphdr *iph, int ip_len, const struct tcphdr *tcph, 
    uint32_t seq, uint32_t ack_seq, int payloadlen, uint16_t window)
{
    tcp_stream_t cur;
    int          ret;

    if (tcph->syn && !tcph->ack) {
        /* handle the SYN */
        ret = filter_syn_packet(mmt, iph->daddr, tcph->dest);
        if (!ret) {
            fprintf(stderr, "refusing SYN packet.\n");
            send_tcp_packet_standalone(mmt, iph->daddr, tcph->dest, 
                iph->saddr, tcph->source, 0, seq + payloadlen + 1, 0, 
                TCP_FLAG_RST | TCP_FLAG_ACK, NULL, 0, cur_ts, 0);
            return NULL;
        }

        /* now accept the new connection */
        cur = handle_passive_open(mmt, cur_ts, iph, tcph, seq, window);
        if (!cur) {
            fprintf(stderr, "No available space in flow pool.\n");
            send_tcp_packet_standalone(mmt, iph->daddr, tcph->dest, 
                iph->saddr, tcph->source, 0, seq + payloadlen + 1, 0, 
                TCP_FLAG_RST | TCP_FLAG_ACK, NULL, 0, cur_ts, 0);
            return NULL;
        }

        return cur;
    } else if (tcph->rst) {
        fprintf(stderr, "RST packet come in.\n");
        /* for the reset packet, just discard */
        return NULL;
    } else {
        fprintf(stderr, "weird packet come in\n");
        /* TODO: for else, discard and send a RST */
        /* if the ACK bit is off, response with seq 0 :<seq=0><ack=seg.seq+seg.len><ctrl=rst|ack>
         * if the ACK bit is on,                      :<seq=seg.ack><ctrl=rst>*/
        if (tcph->ack) {
            send_tcp_packet_standalone(mmt, iph->daddr, tcph->dest, iph->saddr,
                tcph->source, ack_seq, 0, 0, TCP_FLAG_RST, NULL, 0, cur_ts, 0);
        } else {
            send_tcp_packet_standalone(mmt, iph->daddr, tcph->dest, iph->saddr,
                tcph->source, 0, seq + payloadlen, 0, TCP_FLAG_RST, 
                NULL, 0, cur_ts, 0);
        }

        return NULL;
    }
}

/* handle tcp state listen */
inline void 
handle_tcp_state_listen(mmutcpd_manager_t mmt, uint32_t cur_ts, 
    tcp_stream_t cur, struct tcphdr *tcph)
{
    if (tcph->syn) {
        cur->state = TCP_SYN_RECV;
        cur->rcv_nxt++;
        fprintf(stderr, "stream %d: TCP_SYN_RECV\n", cur->id);
        add_to_control_list(mmt, cur, cur_ts);
    } else {
        fprintf(stderr, "stream %d(%s): packet without SYN.\n", 
            cur->id, tcp_state_str[cur->state]);
    }
}

/* handle tcp state syn sent */
/* active open */
inline void 
handle_tcp_state_syn_sent(mmutcpd_manager_t mmt, uint32_t cur_ts, 
tcp_stream_t cur, struct tcphdr *tcph)
{
    int ret;
    /* when active open */
    if (tcph->ack) {
        /* filter the unacceptable acks */
        if (TCP_SEQ_LEQ(ack_seq, cur->snd_var->iss) || 
            TCP_SEQ_GT(ack_seq, cur->snd_nxt)) {
            if (!tcph->rst) {
                send_tcp_packet_standalone(mmt, iph->daddr, tcph->dest, 
                    iph->saddr, tcph->source, ack_seq, 0, 0, TCP_FLAG_RST, 
                    NULL, 0, cur_ts, 0);
            }
            return;
        }
        /* accept the ack */
        cur->snd_var->snd_una++;
    } 

    if (tcph->rst) {
        if (tcph->ack) {
            cur->state = TCP_CLOSE_WAIT;
            cur->close_reason = TCP_RESET;
            if (cur->sk) {
                raise_error_event(mmt, cur);
            } else {
                destroy_tcp_stream(mmt, cur);
            }
        }
        return;
    }

    if (tcph->syn) {
        if (tcph->ack) {
            ret = handle_active_open(mmt, cur, cur_ts, tcph, 
                seq, ack_seq, window);
            if (!ret) {
                return;
            }

            cur->snd_var->nrtx = 0;
            cur->rcv_nxt = cur->rcv_var->irs + 1;
            remove_from_rto_list(mmt, cur);
            cur->state = TCP_ESTABLISHED;
            fprintf(stderr, "stream %d: TCP_ESTABLISHED\n", cur->id);

            if (cur->sk) {
                raise_write_event(mmt, cur);
            } else {
                fprintf(stderr, 
                    "stream %d: TCP_ESTABLISHED, but no socket\n", cur->id);                
                send_tcp_packet_standalone(mmt, iph->daddr, tcph->dest, 
                    iph->saddr, tcph->source, 0, seq + payloadlen + 1, 0, 
                    TCP_FLAG_RST | TCP_FLAG_ACK, NULL, 0, cur_ts, 0);
                cur->close_reason = TCP_ACTIVE_CLOSE;
                destroy_tcp_stream(mmt, cur);
            }
            add_to_control_list(mmt, cur, cur_ts);
            if (m_config.timeout > 0) {
                add_to_timeout_list(mmt, cur);
            }
        } else {
            cur->state = TCP_SYN_RECV;
            fprintf(stderr, "stream %d: TCP_SYN_RECV\n", cur->id);
            cur->snd_nxt = cur->snd_var->iss;
            add_to_control_list(mmt, cur, cur_ts);
        }
    }
}

/* handle tcp state syn recv */
inline void 
handle_tcp_state_syn_recv(mmutcpd_manager_t mmt, uint32_t cur_ts, 
    tcp_stream_t cur, struct tcphdr *tcph, uint32_t ack_seq)
{
    tcp_send_vars_t snd_var = cur->snd_var;
    tcp_recv_vars_t rcv_var = cur->rcv_var;
    tcp_listener_t  listener;
    uint32_t        cwnd_prev;
    int             ret;
    if (tcph->ack) {
        /* check if ACK of SYN */
        if (ack_seq != snd_var->iss + 1) {
            fprintf(stderr, "stream %d(TCP_SYN_RECV): weird ack_seq:%u, iss:%u\n", 
                cur->id, ack_seq, snd_var->iss);
            fprintf(stderr, "stream %d(TCP_SYN_RECV): weird ack_seq:%u, iss:%u\n", 
                cur->id, ack_seq, snd_var->iss);
            return ;
        }

        snd_var->snd_una++;
        cur->snd_nxt = ack_seq;
        cwnd_prev = snd_var->cwnd;
        snd_var->cwnd = ((cwnd_prev == 1) ? (snd_var->mss * 2):snd_var->mss);
        snd_var->nrtx = 0;
        cur->rcv_nxt = cur->rcv_var->irs + 1;
        remove_from_rto_list(mmt, cur);

        cur->state = TCP_ESTABLISHED;
        fprintf(stderr, "stream %d: TCP_ESTABLISHED\n", cur->id);

        /* update listening socket */
        listener = mmt->listener;
        ret = stream_enqueue(listener->acceptq, cur);
        if (ret < 0) {
            fprintf(stderr, "stream %d: failed to enqueue to the" 
                "listen backlog.\n", cur->id);
            cur->close_reason = TCP_NOT_ACCEPTED;
            cur->state = TCP_CLOSE;
            add_to_control_list(mmt, cur);
        }

        fprintf(stderr, "stream %d: insert into acceptq\n", cur->id);
        if (m_config.timeout > 0) {
            add_to_timeout_list(mmt, cur);
        }

        /* raise a event to the listening socket */
        if (listener->sk && (listener->sk->epoll & EPOLL_IN)) {
            add_epoll_event(mmt->ep, MMUTCPD_EVENT_QUEUE, 
                listener->sk, EPOLL_IN);
        }
    } else {
        fprintf(stderr, "stream %d: TCP_SYN_RECV, no ack.\n", cur->id);
        /* retransmit syn/ack */
        cur->snd_nxt = snd_var->iss;
        add_to_control_list(mmt, cur, cur_ts);
    }
}

/* handle tcp state established */
inline void 
handle_tcp_state_established(mmutcpd_manager_t mmt, uint32_t cur_ts, 
    tcp_stream_t cur, struct tcphdr *tcph, uint32_t seq, uint32_t ack_seq, 
    uint8_t *payload, int payloadlen, uint16_t window)
{
    if (tcph->syn) {
        fprintf(stderr, "stream %d: (TCP_ESTABLISHED): weird SYN. "
            "seq:%u, expected:%u, ack_seq:%u, expected:%u\n", 
            cur->id, seq, cur->rcv_nxt, ack_seq, cur->snd_nxt);
        cur->snd_nxt = ack_seq;
        add_to_control_list(mmt, cur);
        return;
    }

    if (payloadlen > 0) {
        if (process_tcp_payload(mmt, cur, cur_ts, payload, seq, payloadlen)) {
            /* if return is TRUE, send ACK */
            enqueue_ack(mmt, cur, cur_ts, ACK_OPT_AGGREGATE);// ??? 
        } else {
            enqueue_ack(mmt, cur, cur_ts, ACK_OPT_NOW);
        }
    }

    if (tcph->ack) {
        if (cur->snd_var->sndbuf) {
            process_ack(mmt, cur, cur_ts, tcph, 
                seq, ack_seq, window, payloadlen);
        }
    }

    if (tcph->fin) {
        /* process the FIN only if the sequence is valid */
        /* FIN packet is allowed to push payload 
         * (should we check PSH flag ??? ) */
        if (seq + payloadlen == cur->rcv_nxt) {
            cur->state = TCP_CLOSE_WAIT;
            fprintf(stderr, "stream %d: TCP_CLOSE_WAIT\n", cur->id);
            cur->rcv_nxt++;
            add_to_control_list(mmt, cur, cur_ts);
            /* notify to app */
            raise_read_event(mmt, cur);
        } else {
            enqueue_ack(mmt, cur, cur_ts, ACK_OPT_NOW);
            return;
        }
    }
}

/* handle tcp state close wait */
inline void 
handle_tcp_state_close_wait(mmutcpd_manager_t mmt, uint32_t cur_ts, 
    tcp_stream_t cur, struct tcphdr *tcph, uint32_t seq, uint32_t ack_seq, 
    int payloadlen, uint16_t window)
{
    if (TCP_SEQ_LT(seq, cur->rcv_nxt)) {
        fprintf(stderr, "stream %d(TCP_CLOSE_WAIT): weird seq:%u, "
            "expected:%u\n", cur->id, seq, cur->rcv_nxt);
        add_to_control_list(mmt, cur, cur_ts);
        return;
    }

    if (cur->snd_var->sndbuf) {
        process_ack(mmt, cur, cur_ts, tcph, seq, ack_seq, 
            window, payloadlen);
    }
}

/* handle tcp state last ack(to ack FIN) */
inline void 
handle_tcp_state_last_ack(mmutcpd_manager_t mmt, uint32_t cur_ts, 
    const struct iphdr *iph, int ip_len, tcp_stream_t cur, 
    struct tcphdr *tcph, uint32_t seq, uint32_t ack_seq, 
    int payloadlen, uint16_t window)
{
    if (TCP_SEQ_LT(seq, cur->rcv_nxt)) {
        fprintf(stderr, "stream %d(TCP_LAST_ACK): weird seq:%u, "
            "expected:%u\n", cur->id, seq, cur->rcv_nxt);
        return;
    }

    if (tcph->ack) {
        if (cur->snd_var->sndbuf) {
            process_ack(mmt, cur, cur_ts, tcph, seq, ack_seq, 
                window, payloadlen);
        }

        if (!cur->snd_var->is_fin_sent) {
            /* the case that FIN is not sent yet */
            /* this is not ack for FIN, ignore */
            return;
        }

        /* check if ACK of FIM */
        if (ack_seq == cur->snd_var->fss + 1) {
            cur->snd_var->snd_una++;
            update_rto_timer(mmt, cur, cur_ts);
            cur->state = TCP_CLOSE;
            cur->close_reason = TCP_PASSIVE_CLOSE;
            fprintf(stderr, "stream %d(TCP_CLOSE):\n", cur->id);
            destroy_tcp_stream(mmt, cur, cur_ts);
        } else {
            fprintf(stderr, "stream %d(TCP_LAST_ACK): not ack of FIN. "
                "ack_seq:%u, expected:%u\n", cur->id, ack_seq, 
                cur->snd_var->fss + 1);
            add_to_control_list(mmt, cur, cur_ts);
        }
    } else {
        fprintf(stderr, "stream %d(TCP_LAST_ACK): not ack\n", cur->id);
        add_to_control_list(mmt, cur, cur_ts);
    }
}

/* handle tcp state fin_wait1 */
inline void 
handle_tcp_state_fin_wait1(mmutcpd_manager_t mmt, uint32_t cur_ts, 
    tcp_stream_t cur, struct tcphdr *tcph, uint32_t seq, uint32_t ack_seq, 
    uint8_t *payload, int payloadlen, uint16_t window)
{
    if (TCP_SEQ_LT(seq, cur->rcv_nxt)) {
        fprintf(stderr, "stream %d(TCP_FIN_WAIT1): weird seq:%u, "
            "expected:%u\n", cur->id, seq, cur->rcv_nxt);
        add_to_control_list(mmt, cur, cur_ts);
        return;
    }

    if (tcph->ack) {
        if (cur->snd_var->sndbuf) {
            process_ack(mmt, cur, cur_ts, tcph, seq, ack_seq, 
                windowm, payloadlen);
        }

        if (cur->snd_var->is_fin_sent && 
            ack_seq == cur->snd_var->fss + 1) {
            cur->snd_var->snd_una = ack_seq;
            if (TCP_SEQ_GT(ack_seq, cur->snd_nxt)) {
                fprintf(stderr, "stream %d(TCP_FIN_WAIT1): "
                    "update snd_nxt to %u\n", cur->id, ack_seq);
                cur->snd_nxt = ack_seq;
            }

            cur->snd_var->nrtx = 0;
            remove_from_rto_list(mmt, cur);
            cur->state = TCP_FIN_WAIT2;
            fprintf(stderr, "stream %d(TCP_FIN_WAIT2)\n", cur->id);
        }
    } else {
        fprintf(stderr, "stream %d: not a ack\n", cur->id);
        return;
    }

    if (payloadlen > 0) {
        if (process_tcp_payload(mmt, cur, cur_ts, payload, seq, payloadlen)) {
            /* if return is TRUE, send ACK */
            enqueue_ack(mmt, cur, cur_ts, ACK_OPT_AGGREGATE);
        } else {
            enqueue_ack(mmt, cur, cur_ts, ACK_OPT_NOW);
        }
    }

    if (tcph->fin) {
        /* process the FIN only if the sequence is valid */
        /* FIN packet is allowed to push payload */
        if (seq + payloadlen == cur->rcv_nxt) {
            cur->rcv_nxt++;

            if (cur->state == TCP_FIN_WAIT1) {
                cur->state = TCP_CLOSING;
                fprintf(stderr, "stream %d(TCP_CLOSING)\n", cur->id);
                add_to_timewait_list(mmt, cur, cur_ts);
            } else if (cur->state == TCP_FIN_WAIT2) {
                cur->state = TCP_TIME_WAIT;
                fprintf(stderr, "stream %d(TCP_TIME_WAIT)\n", cur->id);
                add_to_timewait_list(mmt, cur, cur_ts);
            }
            add_to_control_list(mmt, cur, cur_ts);
        }
    }
}

/* handle tcp state fin_wait2 */
inline void 
handle_tcp_state_fin_wait2(mmutcpd_manager_t mmt, uint32_t cur_ts, 
    tcp_stream_t cur, struct tcphdr *tcph, uint32_t seq, uint32_t ack_seq, 
    uint8_t *payload, int payloadlen, uint16_t window)
{
    if (tcph->ack) {
        if (cur->snd_var->sndbuf) {
            process_ack(mmt, cur, cur_ts, tcph, 
                seq, ack_seq, window, payloadlen);
        }
    } else {
        fprintf(stderr, "stream %d: not contain ack!\n", cur->id);
        return ;
    }

    if (payloadlen > 0) {
        if (process_tcp_payload(mmt, cur, cur_ts, payload, seq, payloadlen)) {
            /* if return is true, send ack */
            enqueue_ack(mmt, cur, cur_ts, ACK_OPT_AGGREGATE);
        } else {
            enqueue_ack(mmt, cur, cur_ts, ACK_OPT_NOW);
        }
    }

    if (tcph->fin) {
        /* process the FIN only if the sequence is valid */
        /* FIN pkt is allowed to push payload (PSH ??) */
        if (seq + payloadlen == cur->rcv_nxt) {
            cur->rcv_nxt++;
            fprintf(stderr, "stream %d: TCP_TIME_WAIT\n", cur->id);
            add_to_timewait_list(mmt, cur, cur_ts);
            add_to_control_list(mmt, cur, cur_ts);
        }
    }
}

/* handle tcp state closing */
inline void 
handle_tcp_state_closing(mmutcpd_manager_t mmt, uint32_t cur_ts, 
    tcp_stream_t cur, struct tcphdr *tcph, uint32_t seq, uint32_t ack_seq, 
    int payloadlen, uint16_t window)
{
    if (tcph->ack) {
        if (cur->snd_var->sndbuf) {
            process_ack(mmt, cur, cur_ts, tcph, seq, ack_seq, 
                window, payloadlen);
        }

        if (!cur->snd_var->is_fin_sent) {
            fprintf(stderr, "stream %d(TCP_CLOSING):no FIN sent yet\n", 
                cur->id);
            return;
        }

        /* check if ACK of FIN */
        if (ack_seq != cur->snd_var->fss + 1) {
            /* if the packet is not ack of FIN, ignore */
            return;
        }

        cur->snd_var->snd_una = ack_seq;
        cur->snd_nxt = ack_seq;
        update_rto_timer(mmt, cur, cur_ts);
        
        cur->state = TCP_TIME_WAIT;
        fprintf(stderr, "stream %d(TCP_CLOSING)\n", cur->id);
        add_to_timewait_list(mmt, cur, cur_ts);
    } else {
        fprintf(stderr, "stream %d(TCP_TIME_WAIT)\n", cur->id);
        return;
    }
}

/* handle tcp state time wait */
inline void 
handle_tcp_state_timewait(mmutcpd_manager_t mmt, uint32_t cur_ts, 
    tcp_stream_t cur)
{
    if (cur->on_timewait_list) {
        remove_from_timewait_list(mmt, cur);
        add_to_timewait_list(mmt, cur);
    }
    add_to_control_list(mmt, cur, cur_ts);
}

/* process tcp packet */
int process_tcp_packet(mmutcpd_manager_t mmt, uint32_t cur_ts, 
    const iphdr *iph, int ip_len)
{
    struct tcphdr *tcph = (struct tcphdr*)( (u_char *)iph + (iph->ihl << 2) );
    uint8_t       *payload = (uint8_t *)tcph + (tcph->doff << 2);
    int           payloadlen = ip_len - (payload - (u_char *)iph);
    tcp_stream    s_stream;/* TODO: can be optimised ?? */
    tcp_stream_t  cur = NULL;
    uint32_t      seq = ntohl(tcph->seq);
    uint32_t      ack_seq = ntohl(tcph->ack_seq);
    uint16_t      window = ntohs(tcph->window);
    uint16_t      check;
    int           ret;

    /* check ip check invalidation */
    /* TODO: offload to nic */
    if (ip_len < (iph->ihl + tcph->doff) << 2 )
        return ERROR;

#if TCP_CALC_CHECKSUM /* TODO: offload */
    check = tcp_calc_check((uint16_t *)tcph, 
        (tcph->doff << 2) + payloadlen, iph->saddr, iph->daddr);
    if (check) {
        tcph->check = 0;
        fprintf(stderr, "stream %d: checksum failed. original, calced:\n", 
            check, tcp_calc_check((uint16_t *)tcph, 
                (tcph->doff << 2) + payloadlen, iph->saddr, iph->daddr));
        return ERROR;
    }
#endif /* TCP_CALC_CHECKSUM */

    s_stream.saddr = iph->daddr;
    s_stream.sport = tcph->dest;
    s_stream.daddr = iph->saddr;
    s_stream.dport = tcph->source;

    if (!(cur = search_tcp_flow_hashtable(mmt->tcp_flow_hstable, s_stream))) {
        /* not found in flow table */
        cur = create_new_flow_hashtable_entry(mmt, cur_ts, iph, ip_len, 
            tcph, seq, ack_seq, payloadlen, window);
        if (!cur) {
            return TRUE;
        }
    }

    /* validate sequence. if not valid, ignore the packrt */
    if (cur->state > TCP_SYN_RECV) {
        ret = validate_sequence(mmt, cur, cur_ts, tcph, 
            seq, ack_seq, payloadlen);
        if (!ret) {
            fprintf(stderr, "stream %d: invalid seq:%u, expected:%u\n", 
                cur->id, seq, cur->rcv_nxt);
            return TRUE;
        }
    }

    /* update recive window size */
    if (tcph->syn) {
        cur->snd_var->peer_wnd = window;
    } else {
        cur->snd_var->peer_wnd = (uint32_t)window << cur->snd_var->wscale; 
    }

    cur->last_active_ts = cur_ts;
    update_timeout_list(mmt, cur_ts);

    /* process RST, process here only if state > TCP_SY_SENT */
    if (tcph->rst) {
        cur->have_reset = TRUE;
        if (cur->state > TCP_SYN_SENT) {
            if (process_rst(mmt, cur, ack_seq)) {
                return TRUE;
            }
        }
    }

    switch (cur->state) {
        case TCP_LISTEN:
            handle_tcp_state_listen(mmt, cur_ts, cur, tcph);
            break;

        case TCP_SYN_SENT:
            handle_tcp_state_syn_sent(mmt, cur_ts, cur, iph, tcph, 
                seq, ack_seq, payloadlen, window);
            break;

        case TCP_SYN_RECV:
            if (tcph->syn && seq == cur->rcv_var->irs) {
                handle_tcp_state_listen(mmt, cur_ts, cur, tcph);
            } else {
                handle_tcp_state_syn_recv(mmt, cur_ts, cur, tcph, ack_seq);  
            }
            break;
        
        case TCP_ESTABLISHED:
            handle_tcp_state_established(mmt, cur_ts, cur, tcph, seq, ack_seq, 
                payload, payloadlen, window);
            break;

        case TCP_CLOSE_WAIT:
            handle_tcp_state_close_wait(mmt, cur_ts, cur, tcph, seq, ack_seq, 
                payloadlen, window);
            break;

        case TCP_LAST_ACK:
            handle_tcp_state_last_ack(mmt, cur_ts, iph, ip_len, cur, tcph, 
                seq, ack_seq, payloadlen, window);
            break;

        case TCP_FIN_WAIT1:
            handle_tcp_state_fin_wait1(mmt, cur_ts, cur, tcph, seq, ack_seq, 
                payload, payloadlen, window);
            break;

        case TCP_FIN_WAIT2:
            handle_tcp_state_fin_wait2(mmt, cur_ts, cur, tcph, seq, ack_seq, 
                payload, payloadlen, window);
            break;

        case TCP_CLOSING:
            handle_tcp_state_closing(mmt, cur_ts, cur, tcph, seq, ack_seq, 
                payloadlen, window);
            break;

        case TCP_TIME_WAIT:
            /* goto here, only when a restransmission of the remote FIN. 
             * ack it and restart a 2MSL timeout */
            handle_tcp_state_timewait(mmt, cur_ts, cur);
            break;

        case TCP_CLOSE:
            break;

        default :
            break;

    }

    return TRUE;
}
#endif /* tcp_in */

/* remove from control list */
inline void 
remove_from_control_list(mmutcpd_manager_t mmt, tcp_stream_t cur)
{
    mmutcpd_sender_t sender = g_sender(mmt, cur);
    if (cur->snd_var->on_control_list) {
        cur->snd_var->on_control_list = FALSE;
        TAILQ_REMOVE(&sender->control_list, cur, snd_var->control_link);
        sender->control_list_cnt--;
    }
}

/* remove from send list */
inline void
remove_from_send_list(mmutcpd_manager_t mmt, tcp_stream_t cur)
{
    mmutcpd_sender_t sender = g_sender(mmt, cur);
    if (cur->snd_var->on_send_list) {
        cur->snd_var->on_send_list = FALSE;
        TAILQ_REMOVE(&sender->on_send_list, cur, snd_var->send_link);
        sender->send_list_cnt--;
    }
}

/* remove from ack list */
inline void
remove_from_ack_list(mmutcpd_manager_t mmt, tcp_stream_t cur)
{
    mmutcpd_sender_t sender = g_sender(mmt, cur);
    if (cur->snd_var->on_ack_list) {
        cur->snd_var->on_ack_list = FALSE;
        TAILQ_REMOVE(&sender->ack_list, cur, snd_var->ack_link);
        sender->ack_list_cnt--;
    }
}


/* add to timeout list */
inline void 
add_to_timeout_list(mmutcpd_manager_t mmt, tcp_stream_t cur)
{
    if (cur->on_timeout_list) {
        assert(0);
        return;
    }

    cur->on_timeout_list = TRUE;
    TAILQ_INSERT_TAIL(&mmt->timeout_list, cur, snd_var->timeout_link);
    mmt->timeout_list_cnt++;
}

/* remove from timeout list */
inline void
remove_from_timeout_list(mmutcpd_manager_t mmt, tcp_stream_t cur)
{
    if (cur->on_timeout_list) {
        cur->on_timeout_list = FALSE;
        TAILQ_REMOVE(&mmt->timeout_list, cur, snd_var->timeout_link);
        mmt->timeout_list_cnt--;
    }
}

/* update timeout list */
inline void 
update_timeout_list(mmutcpd_manager_t mmt, tcp_stream_t cur)
{
    if (cur->on_timeout_list) {
        TAILQ_REMOVE(&mmt->timeout_list, cur, snd_var->timeout_link);
        TAILQ_INSERT_TAIL(&mmt->timeout_list, cur, snd_var->timeout_link);        
    }
}

/* check connection timeout */
void 
chekc_conn_timeout(mmutcpd_manager_t mmt, uint32_t cur_ts, int thresh);
{
    tcp_stream_t tmp;
    tcp_stream_t next;
    int          cnt;

    cnt = 0;
    for (tmp = TAILQ_FIRST(&mmt->timeout_list); tmp !=NULL; tmp = next) {
        if (++cnt > thresh) {
            break;
        }
        next = TAILQ_NEXT(tmp, snd_var->timeout_link);

        if ((int32_t)(cur_ts - tmp->last_active_ts) >= TCP_TIMEOUT_VAL ) {
            tmp->on_timeout_list = FALSE;
            TAILQ_REMOVE(&mmt->timeout_list, tmp, snd_var->timeout_link);
            mmt->timeout_list_cnt--;
            tmp->state = TCP_TIMEOUT;
            if (tmp->sk) {
                raise_error_event(mmt, cur);
            } else {
                destroy_tcp_stream(mmt, cur);
            }
        } else {
            break;
        }
    }
}

/* add to timewait list */
include void 
add_to_timewait_list(mmutcpd_manager_t mmt, tcp_stream_t cur, uint32_t cur_ts)
{
    cur->rcv_var->ts_tw_expire = cur_ts + TCP_TIMEWAIT_VAL;

    if (cur->on_timewait_list) {
        /* update list in sorted way by ts_tw_expire */
        TAILQ_REMOVE(&mmt->timewait_list, cur, snd_var->timer_link);
        TAILQ_INSERT_TAIL(&mmt->timewait_list, cur, snd_var->timer_link);
    } else {
        if (cur->on_rto_idx >= 0) {
            remove_from_rto_list(mmt, cur);
        }

        cur->on_timewait_list = TRUE;
        TAILQ_INSERT_TAIL(&mmt->timewait_list, cur, snd_var->timer_link);
        mmt->timewait_list_cnt++;
    }

}

/* remove from timewait list */
inline void
remove_from_timewait_list(mmutcpd_manager_t mmt, tcp_stream_t cur)
{
    if (!cur->on_timewait_list) {
        assert(0);
        return ;
    }

    TAILQ_REMOVE(mmt->timewait_list, cur, snd_var->timer_link);
    cur->on_timewait_list = FALSE;
    mmt->timewait_list_cnt--;
}

/* check timewait expire */
void 
check_timewait_expire(mmutcpd_manager_t mmt, uint32_t cur_ts, int thresh)
{
    tcp_stream_t tmp;
    tcp_stream_t next;
    int          cnt = 0;

    for (tmp = TAILQ_FIRST(&mmt->timewait_list); tmp !=NULL; tmp = next) {
        if (++cnt > thresh) {
            break;
        }
        next = TAILQ_NEXT(tmp, snd_var->timer_link);
        fprintf(stderr, "stream %d: inside check timewait list. cnt:%u\n", 
            cur->id, cnt);
        if (tmp->on_timewait_list) {
            if ((int32_t)(cur_ts - tmp->rcv_var->ts_tw_expire) >= 0 ) {
                if (!tmp->snd_var->on_control_list) {
                    TAILQ_REMOVE(&mmt->timewait_list, tmp, timer_link);
                    tmp->on_timewait_list = FALSE;
                    mmt->timewait_list_cnt--;

                    tmp->state = TCP_CLOSE;
                    tmp->close_reason = TCP_ACTIVE_CLOSE;
                    fprintf(stderr, "stream %d: TCP_CLOSE.%s\n", cur->id);
                    destroy_tcp_stream(mmt, tmp);
                }
            } else {
                break;
            }
        } else {
            fprintf(stderr, "stream %d: not on timewait_list.\n", tmp->id);
        }
    }
}

/* init rto_hashstore in mmutcpd, named rto_store */
rto_hashstore_t
init_rto_hashstore()
{
    int i;
    rto_hashstore_t hs = calloc(1, sizeof(struct rto_hashstore));
    if (!hs) {
        fprintf(stderr, "calloc: init_rto_hashstore%s\n", );
        return 0;
    }

    for (i = 0; i < RTO_HASH; i++) {
        TAILQ_INIT(&hs->rto_list[i]);
    }

    TAILQ_INIT(&hs->rto_list[RTO_HASH]);
    return hs;
}

/* add to rto list */
inline void 
add_to_rto_list(mmutcpd_manager_t mmt, tcp_stream_t cur)
{
    if (!mmt->rto_list_cnt) {
        mmt->rto_store->rto_now_idx = 0;
        mmt->rto_store->rto_now_ts = cur->snd_var->ts_rto;
    }

    if (cur->on_rto_idx < 0) {
        if (cur->on_timewait_list) {
            /* cant be both in tw_list and rto_list */
            return;
        }

        int diff = (int32_t)(cur->snd_var->ts_rto - mmt->rto_store->rto_now_ts);
        if (diff < RTO_HASH) {
            int offset = (diff + mmt->rto_store->rto_now_idx) % RTO_HASH;
            cur->on_rto_idx = offset;
            TAILQ_INSERT_TAIL(&mmt->rto_store->rto_list[offset], 
                cur, snd_var->timer_link);
        } else {
            cur->on_rto_idx = RTO_HASH;
            TAILQ_INSERT_TAIL(&mmt->rto_store->rto_list[RTO_HASH], 
                cur, snd_var->timer_link);
        }
        mmt->rto_list_cnt++;
    }
}

/* remove from rto list */
inline void
remove_from_rto_list(mmutcpd_manager_t mmt, tcp_stream_t cur)
{
    if (cur->on_rto_idx < 0) {
        return ;
    }

    TAILQ_REMOVE(&mmt->rto_store->rto_list[cur->on_rto_idx], 
        cur, snd_var->timer_link);
    cur->on_rto_idx = -1;

    mmt->rto_list_cnt--;
}

/* update retransmission timer */
inline void
update_rto_timer(tcp_stream_t cur, cur_ts)
{
    /* update the retransmission timer */
    assert(cur->snd_var->rto > 0);
    cur->snd_var->nrtx = 0;

    /* if in rto list, remove it */
    if (cur->on_rto_idx >= 0) {
        remove_from_rto_list(mmt, cur);
    }

    /* reset retransmission timeout */
    if (TCP_SEQ_GT(cur->snd_nxt, cur->snd_var->snd_una)) {
        /* there are packets sent but not acked, update rto timestamp */
        cur->snd_var->ts_rto = cur_ts + cur->snd_var->rto;
        add_to_rto_list(mmt, cur);
    } else {
        /* all packet are acked */
        fprintf(stderr, "stream %d: all packet are acked. snd_una:%u " 
            "snd_nxt:%u\n", cur->snd_var->snd_una, cur->snd_nxt);
    }
}


/* handle rto 
 * a important function */
inline int 
handle_rto(mmutcpd_manager_t mmt, uint32_t cur_ts, tcp_stream_t cur)
{
    uint8_t backoff;

    fprintf(stderr, "stream %d:timeout. rto:%u(%ums), snd_una:%u, snd_nxt:%u\n", 
        cur->id, cur->snd_var->rto, TS_TO_MSEC(cur->snd_var->rto), 
        cur->snd_var->snd_una, cur->snd_nxt);
    assert(cur->snd_var->rto > 0);

    /* count number of retransmission */
    if (cur->snd_var->nrtx < TCP_MAX_RTX) {
        cur->snd_var->nrtx++;
    } else {
        /* if it exceeds the threshold, destroy and notify to app */
        fprintf(stderr, "stream %d:exceeds TCP_MAX_RTX\n", cur->id);
        if (cur->state < TCP_ESTABLISHED) {
            cur->state = TCP_CLOSE;
            cur->close_reason = TCP_CONN_FAIL;
            destroy_tcp_stream(mmt, cur);
        } else {
            cur->state = TCP_CLOSE;
            cur->state->close_reason = TCP_CONN_LOST;
            if (cur->sk) {
                raise_error_event(mmt, cur);
            } else {
                destroy_tcp_stream(mmt, cur);
            }
        }

        return ERROR;
    }

    if (cur->snd_var->nrtx > cur->snd_var->max_nrtx) {
        cur->snd_var->max_nrtx = cur->snd_var->nrtx;
    }

    /* update rto timestamp */
    if (cur->state >= TCP_ESTABLISHED) {
        uint32_t rto_prev;
        backoff = MIN(cur->snd_var->nrtx, TCP_MAX_BACKOFF);

        rto_prev = cur->snd_var->rto;
        cur->snd_var->rto = 
            ((cur->rcv_var->srtt >> 3) + cur->rcv_var->rttvar) << backoff;
        if (cur->snd_var->rto <= 0) {
            fprintf(stderr, "stream %d(%s):current rto:%u, prev:%u\n", 
                cur->id, tcp_state_str[cur->state], 
                cur->snd_var->rto, rto_prev);
            cur->snd_var->rto = rto_prev;
        }
    }
    cur->snd_var->ts_rto = cur_ts + cur->snd_var->rto;

    /* reduce congestion window and ssthresh */
    cur->snd_var->ssthresh = MIN(cur->snd_var->cwnd, cur->snd_var->peer_wnd) / 2;
    if (cur->snd_var->ssthresh < (2*cur->snd_var->mss)) {
        cur->snd_var->ssthresh = cur->snd_var->mss * 2;
    }
    cur->snd_var->cwnd = cur->snd_var->mss;
    fprintf(stderr, "stream %d: timeout. cwnd:%u, ssthresh:%u\n", cur->id, 
        cur->snd_var->cwnd, cur->snd_var->ssthresh);

    /* retransmission */
    switch (cur->state) {
        case TCP_SYN_SENT:/* SYN lost */
            if (cur->snd_var->nrtx > TCP_MAX_SYN_RETRY) {
                cur->state = TCP_CLOSE;
                cur->close_reason = TCP_CONN_FAIL;
                fprintf(stderr, "stream %d: SYN retries "
                    "exceeds max retries\n", cur->id);
                if (cur->sk) {
                    raise_error_event(mmt, cur);
                } else {
                    destroy_tcp_stream(mmt, cur);
                }
                return ERROR;
            }
            fprintf(stderr, "stream %d: re_xmit SYN. "
                "snd_nxt:%u, snd_una:%u\n", cur->id, cur->snd_nxt, 
                cur->snd_var->snd_una);
            break;

        case TCP_SYN_RECV:/* SYN/ACK lost */
            fprintf(stderr, "stream %d: re_xmit SYN/ACK. "
                "snd_nxt:%u, snd_una:%u\n", cur->id, cur->snd_nxt, 
                cur->snd_var->snd_una);
            break;

        case TCP_ESTABLISHED:/* data lost */
            fprintf(stderr, "stream %d: re_xmit data. "
                "snd_nxt:%u, snd_una:%u\n", cur->id, cur->snd_nxt, 
                cur->snd_var->snd_una);
            break;

        case TCP_CLOSE_WAIT:/* data lost */
            fprintf(stderr, "stream %d: re_xmit data. "
                "snd_nxt:%u, snd_una:%u\n", cur->id, cur->snd_nxt, 
                cur->snd_var->snd_una);
            break;

        case TCP_LAST_ACK:/* FIN/ACK lost */
            fprintf(stderr, "stream %d: re_xmit FIN/ACK. "
                "snd_nxt:%u, snd_una:%u\n", cur->id, cur->snd_nxt, 
                cur->snd_var->snd_una);
            break;

        case TCP_FIN_WAIT1:/* FIN lost */
            fprintf(stderr, "stream %d: re_xmit FIN. "
                "snd_nxt:%u, snd_una:%u\n", cur->id, cur->snd_nxt, 
                cur->snd_var->snd_una);
            break;

        case TCP_CLOSING:/* ACK lost */
            fprintf(stderr, "stream %d: re_xmit ACK(at closing state). "
                "snd_nxt:%u, snd_una:%u\n", cur->id, cur->snd_nxt, 
                cur->snd_var->snd_una);
            break;

        default:
            fprintf(stderr, "stream %d(%s): weird state:. "
                "snd_nxt:%u, snd_una:%u\n", cur->id, tcp_state_str[cur->state],
                cur->snd_nxt, cur->snd_var->snd_una);
            assert(0);
            return ERROR;
    }

    cur->snd_nxt = cur->snd_var->snd_una;
    if (cur->state == TCP_ESTABLISHED || cur->state == TCP_CLOSE_WAIT) {
        /* re_xmit data at established state */
        add_to_send_list(mmt, cur);
    } else if (cur->state == TCP_FIN_WAIT1 || 
        cur->state == TCP_CLOSING || cur->state == TCP_LAST_ACK) {
        if (cur->snd_var->fss == 0) {
            fprintf(stderr, "stream %d: fss not set\n", cur->id);
        }
        /* decide to re_xmit data or ctrl pkt */
        if (TCP_SEQ_LT(cur->snd_nxt, cur->snd_var->fss)) {
            /* need to re_xmit data */
            if (cur->snd_var->on_control_list) {
                remove_from_control_list(mmt, cur);
            }
            cur->control_list_waiting = TRUE;
            add_to_send_list(mmt, cur);
        } else {
            /* need to control pkt */
            add_to_control_list(mmt, cur, cur_ts);
        }
    } else {
        add_to_control_list(mmt, cur, cur_ts);
    }

    return 0;
}

/* rearange rto store */
inline void 
rearrange_rto_store(mmutcpd_manager_t mmt)
{
    tcp_stream_t     tmp;
    tcp_stream_t     next;
    struct rto_head* rto_list = &mmt->rto_store->rto_list[RTO_HASH];
    int              cnt = 0;

    for (tmp = TAILQ_FIRST(rto_list); tmp != NULL; tmp = next) {
        next = TAILQ_NEXT(tmp, snd_var->timer_link);
        int diff = (int32_t)(mmt->rto_store->rto_now_ts - tmp->snd_var->ts_rto);
        if (diff < RTO_HASH) {
            int offset = (diff + mmt->rto_store->rto_now_idx) % RTO_HASH;
            TAILQ_REMOVE(&mmt->rto_store->rto_list[RTO_HASH], 
                tmp, snd_var->timer_link);
            tmp->on_rto_idx = offset;
            TAILQ_INSERT_TAIL(&mmt->rto_store->rto_list[offset], 
                tmp, snd_var->timer_link);
        }
        cnt++;
    }
}

/* check retransmission timeout */
void
check_rto_timeout(mmutcpd_manager_t mmt, uint32_t cur_ts, int thresh)
{
    tcp_stream_t tmp;
    tcp_stream_t next;
    /* TODO: learn this writing way */
    struct       rto_head* rto_list;
    int          cnt  = 0;
    int          ret;

    if (!mmt->rto_list_cnt) {
        return;
    }

    while (1) {
        rto_list = &mmt->rto_store->rto_list[mmt->rto_store->rto_now_idx];
        if ((int32_t)(cur_ts - mmt->rto_store->rto_now_ts) < 0) {
            break;
        }

        for (tmp = TAILQ_FIRST(rto_list); tmp != NULL; tmp = next) {
            if (++cnt > thresh) {
                break;
            }
            next = TAILQ_NEXT(tmp, timer_link);
            fprintf(stderr, "stream %d: in rto_list. cnt:%u\n", cur->id, cnt);
            if (tmp->on_rto_idx >= 0) {
                ret = handle_rto(mmt, cur_ts, tmp);
                TAILQ_REMOVE(rto_list, tmp, snd_var->timer_link);
                mmt->rto_list_cnt--;
                tmp->on_rto_idx = -1;
            } else {
                fprintf(stderr, "stream %d: not on a rto list\n", cur->id);
            }
        }

        if (cnt > thresh) {
            break
        } else {
            mmt->rto_store->rto_now_idx = ( mmt->rto_store->rto_now_idx + 1) % RTO_HASH;
            mmt->rto_store->rto_now_ts++;
            if (!(mmt->rto_store->rto_now_idx % 1000)) {
                rearrange_rto_store(mmt);
            }
        }
    }
}

#endif /* tcp_out */