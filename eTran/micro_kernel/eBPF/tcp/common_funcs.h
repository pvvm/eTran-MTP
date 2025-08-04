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