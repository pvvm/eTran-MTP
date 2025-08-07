#include "runtime/tcp.h"

#ifndef CTRL_PLANE_MTP
#define CTRL_PLANE_MTP

struct interm_out {
    __u64 curr_tsc;
};

//#define MTP_ON 1

// Question: here I'm considering that the compiler will simply get a snapshot
// of ALL values of the map, even if it doesn't make much sense, like rate
// (also, I'm considering that tcp_connection will have an entry for each too)
static inline void mtp_snapshot_cc(struct timer_event *ev, struct tcp_connection *c, eTranTCP *etran_tcp)
{
    __u32 cc_idx = c->cc_idx;
    c->cnt_tx_drops     = etran_tcp->_tcp_cc_map_mmap->entry[cc_idx].cnt_tx_drops;
    c->cnt_rx_acks      = etran_tcp->_tcp_cc_map_mmap->entry[cc_idx].cnt_rx_acks;
    c->cnt_rx_ack_bytes = etran_tcp->_tcp_cc_map_mmap->entry[cc_idx].cnt_rx_ack_bytes;
    c->cnt_rx_ecn_bytes = etran_tcp->_tcp_cc_map_mmap->entry[cc_idx].cnt_rx_ecn_bytes;
    c->txp      = etran_tcp->_tcp_cc_map_mmap->entry[cc_idx].txp;
    c->rtt_est  = etran_tcp->_tcp_cc_map_mmap->entry[cc_idx].rtt_est;
    c->rate     = etran_tcp->_tcp_cc_map_mmap->entry[cc_idx].rate;
    c->prev_desired_tx_ts   = etran_tcp->_tcp_cc_map_mmap->entry[cc_idx].prev_desired_tx_ts;
    *ev = etran_tcp->_tcp_cc_map_mmap->entry[cc_idx].ev;
}

void slows_congc_ep(struct timer_event *ev, struct tcp_connection *c, struct interm_out *int_out) {

}


#endif