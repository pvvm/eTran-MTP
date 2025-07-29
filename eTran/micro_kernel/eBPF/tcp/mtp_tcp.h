/*#pragma once
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/types.h>

#include <intf/intf_ebpf.h>

#include "../ebpf_utils.h"
#include "../ebpf_queue.h"
#include "eTran_defs.h"
#include "pacing.h"
#include "mtp_defs.h"

#define TCP_ACK_HEADER_CUTOFF (int)(XDP_GEN_PKT_SIZE - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct tcphdr) - TS_OPT_SIZE)

#if defined(XDP_DEBUG) || defined(XDP_EGRESS_DEBUG) || defined(XDP_GEN_DEBUG)
#define TCP_LOCK(c)
#define TCP_UNLOCK(c)
#else
// #define TCP_LOCK(c)
// #define TCP_UNLOCK(c)
#define TCP_LOCK(c) bpf_spin_lock(&c->lock)
#define TCP_UNLOCK(c) bpf_spin_unlock(&c->lock)
#endif

#define NULL_CONN __UINT32_MAX__
// we use cc_idx to identify each connection
// TODO: much more configurable
SEC(".data.prev_conn")
__u32 prev_conn[MAX_CPU] = {__UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__,
                            __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__,
                            __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__,
                            __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__,
};
__u32 prev_conn_li[MAX_CPU];
__u16 prev_conn_lp[MAX_CPU];
__u32 prev_conn_ri[MAX_CPU];
__u16 prev_conn_rp[MAX_CPU];
__u8 prev_conn_ece[MAX_CPU];

// FIXME 
#define TCP_WND_SCALE 3

#define TCP_OPT_END_OF_OPTIONS 0
#define TCP_OPT_NO_OP 1
#define TCP_OPT_MSS 2
#define TCP_OPT_TIMESTAMP 8

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ebpf_flow_tuple);
    __type(value, struct bpf_tcp_conn);
    __uint(max_entries, MAX_TCP_FLOWS);
} bpf_tcp_conn_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct bpf_cc);
    __uint(max_entries, MAX_TCP_FLOWS);
    __uint(map_flags, BPF_F_MMAPABLE);
} bpf_cc_map SEC(".maps");

// ACK
// emulate a per-cpu SCSP queue with BPF_MAP_TYPE_PERCPU_ARRAY
// TODO: adapt this to a pkt_bp that generates acks
struct bpf_tcp_ack {
    __u32 local_ip;
    __u32 remote_ip;
    __u16 local_port;
    __u16 remote_port;

    __u32 seq; // tx_next_seq
    __u32 ack; // rx_next_seq
    __u32 rxwnd; // rx_avail

    __u32 ts_val; // now
    __u32 ts_ecr; // tx_next_ts

    __u8 ecn_flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, NAPI_BATCH_SIZE);
    __type(key, __u32);
    __type(value, struct bpf_tcp_ack);
} bpf_tcp_ack_map SEC(".maps");

SEC(".bss.ack_prod")
__u32 ack_prod[MAX_CPU];
SEC(".bss.ack_cons")
__u32 ack_cons[MAX_CPU];

SEC(".bss.tx_cached_ts")
__u64 tx_cached_ts[MAX_CPU];

SEC(".bss.rx_cached_ts")
__u64 rx_cached_ts[MAX_CPU];*/

#include <stdlib.h>

static __always_inline void rto_ep(struct net_event *ev, struct bpf_tcp_conn *c, struct interm_out *int_out) {
    if(ev->ack_seq < c->rx_next_seq || c->tx_next_seq < ev->ack_seq) {
        int_out->skip_ack_eps = 1;
        return;
    }
    __u32 granularity_g = 1;
    // Question: they calculate RTT, while we use a constant. Should we do the same as them?
    __u32 RTT = 100000000;

    if(c->first_rto) {
        c->SRTT = RTT;
        c->RTTVAR = RTT / 2;
        if(granularity_g >= 4 * c->RTTVAR) {
            c->RTO = c->SRTT + granularity_g;
        } else {
            c->RTO = c->SRTT + 4 * c->RTTVAR;
        }
        c->first_rto = 0;

    } else {
        c->RTTVAR = (1 - 1/4) * c->RTTVAR + 1/4 * llabs(c->SRTT - RTT);
        c->SRTT = (1 - 1/8) * c->SRTT + 1/8 * RTT;
        if(granularity_g >= 4 * c->RTTVAR) {
            c->RTO = c->SRTT + granularity_g;
        } else {
            c->RTO = c->SRTT + 4 * c->RTTVAR;
        }
    }
}

static __always_inline void fast_retr_rec_ep(struct net_event *ev, struct bpf_tcp_conn *c, struct interm_out *int_out) {
    int_out->change_cwnd = 1;
    if(ev->ack_seq == c->last_ack) {
        int_out->change_cwnd = 0;
        c->rx_dupack_cnt += 1;
        if(c->rx_dupack_cnt == 3) {
            c->rx_dupack_cnt = 0;
            __u32 go_back_bytes = c->tx_next_seq - c->rx_next_seq;
            c->tx_next_seq -= go_back_bytes;
            // Cut rate by half
            c->rate >>= 1;
            // Question: in MTP we would have a set_rate function here.
            // But this rate would only be used in XDP_EGRESS and enqueueing the packets to the timing wheel
            // Can we consider the compiler would simply ignore the function?
        }
    } else {
        c->rx_dupack_cnt = 0;
        c->last_ack = ev->ack_seq;
    }
}

static __always_inline int net_ev_dispatcher(struct net_event *ev, struct bpf_tcp_conn *c) {
    struct interm_out int_out;
    if(ev->minor_type == NET_EVENT_ACK) {
        rto_ep(ev, c, &int_out);
        fast_retr_rec_ep(ev, c, &int_out);
    } else if (ev->minor_type == NET_EVENT_DATA) {

    }
    return 0;
}