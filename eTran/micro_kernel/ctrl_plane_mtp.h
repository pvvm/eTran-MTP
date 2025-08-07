#include "runtime/tcp.h"

#ifndef CTRL_PLANE_MTP
#define CTRL_PLANE_MTP

struct interm_out {
    __u64 curr_tsc;
    __u32 win;
    __u32 rtt;
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
    __u32 last;
    last = c->cc_last_drops;
    c->cc_last_drops = c->cnt_tx_drops;
    c->cnt_tx_drops -= last;

    /*last = c->cc_last_acks;
    c->cc_last_acks = c->cnt_rx_acks;
    c->cnt_rx_acks -= last;*/

    last = c->cc_last_ackb;
    c->cc_last_ackb = c->cnt_rx_ack_bytes;
    c->cnt_rx_ack_bytes -= last;

    last = c->cc_last_ecnb;
    c->cc_last_ecnb = c->cnt_rx_ecn_bytes;
    c->cnt_rx_ecn_bytes -= last;

    struct cc_dctcp_wnd *cc = &c->cc_data.dctcp_wnd;
    uint64_t ecn_rate, incr;
    int_out->rtt = c->rtt_est;
    int_out->win = cc->window;

    assert(int_out->win >= 1448);

    /* If RTT is zero, use estimate */
    if (int_out->rtt == 0)
    {
        int_out->rtt = TCP_RTT_INIT;
    }

    c->cc_last_rtt = int_out->rtt;

    // static int print_freq = 10000;
    // if (print_freq-- <= 0) {
    //     print_freq = 10000;
    //     printf("Connection(%p): RTT: %u us, rate(kbps): %u, %d\n", c, rtt, c->cc_rate, cc->slowstart);
    // }

    /* Slow start */
    if (cc->slowstart)
    {
        if (c->cnt_tx_drops == 0 && c->cnt_rx_ecn_bytes == 0 && c->cc_rexmits == 0)
        {
            /* double window, but ensure we don't overflow it */
            if (int_out->win + c->cnt_rx_ack_bytes > int_out->win)
                int_out->win += c->cnt_rx_ack_bytes;
        }
        else
        {
            /* if we see any indication of congestion go into congestion avoidance */
            cc->slowstart = 0;
        }
    }

    /* Congestion avoidance */
    if (!cc->slowstart)
    {
        /* if we have drops, cut by half */
        if (c->cnt_tx_drops > 0 || c->cc_rexmits > 0)
        {
            int_out->win /= 2;
        }
        else
        {
            /* update ECN rate */
            if (c->cnt_rx_ack_bytes > 0)
            {
                c->cnt_rx_ecn_bytes = (c->cnt_rx_ecn_bytes <= c->cnt_rx_ack_bytes ? c->cnt_rx_ecn_bytes : c->cnt_rx_ack_bytes);
                ecn_rate = (((uint64_t)c->cnt_rx_ecn_bytes) * UINT32_MAX) / c->cnt_rx_ack_bytes;

                /* EWMA */
                ecn_rate = ((ecn_rate * CC_DCTCP_WEIGHT) +
                            ((uint64_t)cc->ecn_rate *
                             (UINT32_MAX - CC_DCTCP_WEIGHT)));
                ecn_rate /= UINT32_MAX;
                cc->ecn_rate = ecn_rate;
            }

            /* if ecn marks: reduce window */
            if (c->cnt_rx_ecn_bytes > 0)
            {
                int_out->win = (((uint64_t)int_out->win) * (UINT32_MAX - cc->ecn_rate / 2)) / UINT32_MAX;
            }
            else
            {
                /* additive increase */
                assert(int_out->win != 0);
                incr = ((uint64_t)c->cnt_rx_ack_bytes * 1448) / int_out->win;
                if ((uint32_t)(int_out->win + incr) > int_out->win)
                    int_out->win += incr;
            }
        }
    }

    /* Ensure window is at least 1 mss */
    if (int_out->win < 1448)
        int_out->win = 1448;

    /* A window larger than the send buffer also does not make much sense */
    if (int_out->win > c->tx_buf_size)
        int_out->win = c->tx_buf_size;
    
    c->cc_rexmits = 0;
}

void set_tx_rate(struct timer_event *ev, struct tcp_connection *c, struct interm_out *int_out) {
    uint64_t time, rate;

    /* calculate how long [ns] it will take to send a window size's worth */
    time = (((uint64_t)int_out->win * 8 * 1000) / (MAX_LINK_BANDWIDTH / 1e6)) / 1000;

    /* we won't be able to send more than a window per rtt */
    if (time < int_out->rtt * 1000)
        time = int_out->rtt * 1000;

    /* convert time to rate */
    assert(time != 0);
    rate = ((uint64_t)int_out->win * 8 * 1000000) / time;
    if (rate > UINT32_MAX)
        rate = UINT32_MAX;
    
    c->cc_rate = (uint32_t)rate;
    c->cc_data.dctcp_wnd.window = int_out->win;

    uint32_t v = c->cc_rate * 1e3 / 8;
    if (v > 3125000000)
        v = 3125000000; // 25Gbps
    // Question: is it safe to assume that set_rate function is translated to this?
    etran_tcp->_tcp_cc_map_mmap->entry[c->cc_idx].rate = v;
}


#endif