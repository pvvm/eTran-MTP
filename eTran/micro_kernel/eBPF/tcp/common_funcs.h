#pragma once

#include "../ebpf_queue.h"

#define TCP_WND_SCALE 3


static __always_inline void set_tcp_flag(struct tcphdr *tcph, __u16 len, __u16 flags)
{
    tcph->res1 = 0;
    tcph->doff = len;
    tcph->fin = (flags & TCP_FLAG_FIN) ? 1 : 0;
    tcph->syn = (flags & TCP_FLAG_SYN) ? 1 : 0;
    tcph->rst = (flags & TCP_FLAG_RST) ? 1 : 0;
    tcph->psh = (flags & TCP_FLAG_PSH) ? 1 : 0;
    tcph->ack = (flags & TCP_FLAG_ACK) ? 1 : 0;
    tcph->urg = (flags & TCP_FLAG_URG) ? 1 : 0;
    tcph->ece = (flags & TCP_FLAG_ECE) ? 1 : 0;
    tcph->cwr = (flags & TCP_FLAG_CWR) ? 1 : 0;
}

static __always_inline __u32 xsk_budget_avail(const struct bpf_tcp_conn *c)
{
    return c->rx_remote_avail;
}

/**
 * @brief Given a range [start, end), check if a sequence number is in the range,
 *        considering the wrap-around case. excluding indicates whether the seq is exclusive.
 */
static __always_inline bool seq_in_range(__u32 seq, __u32 start, __u32 end, bool excluding)
{
    if (start <= end) {
        return excluding ? (seq > start && seq <= end) : (seq >= start && seq < end);
    } else {
        return excluding ? (seq > start || seq <= end) : (seq >= start || seq < end);
    }
}

/**
 * @brief out-of-order version of tcp_valid_rxseq()
 *        as long as the pkt seq range has overlap with the receive buffer range,
 *        we consider it as a valid pkt
 */
static __always_inline int tcp_valid_rxseq_ooo(struct bpf_tcp_conn *c, __u32 seq, __u32 payload_len, __u32 *trim_start, __u32 *trim_end)
{
    __u32 exp_seq_first = c->rx_next_seq;
    __u32 exp_seq_last = c->rx_next_seq + c->rx_avail;

    __u32 pkt_seq_first = seq;
    __u32 pkt_seq_last = seq + payload_len;

    xdp_log("exp_seq_first(%u), exp_seq_last(%u), pkt_seq_first(%u), pkt_seq_last(%u)", exp_seq_first, exp_seq_last, pkt_seq_first, pkt_seq_last);

    bool valid = seq_in_range(pkt_seq_first, exp_seq_first, exp_seq_last, false) ||
                 seq_in_range(pkt_seq_last, exp_seq_first, exp_seq_last, true) ||
                 seq_in_range(exp_seq_first, pkt_seq_first, pkt_seq_last, false) ||
                 seq_in_range(exp_seq_last, pkt_seq_first, pkt_seq_last, true);
    
    if (!valid) {
        return -1;
    }

    if (seq_in_range(pkt_seq_first, exp_seq_first, exp_seq_last, false)) {
        *trim_start = 0;
    } else {
        *trim_start = exp_seq_first - pkt_seq_first;
    }

    if (seq_in_range(pkt_seq_last, exp_seq_first, exp_seq_last, true)) {
        *trim_end = 0;
    } else {
        *trim_end = pkt_seq_last - exp_seq_last;
    }

    xdp_log("*trim_start(%u), *trim_end(%u)", *trim_start, *trim_end);

    return 0;
}