#pragma once
/*#include <bpf/bpf_helpers.h>
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
#include "common_funcs.h"

// Fill TCP header excpet for ports
static __always_inline void mtp_fill_tcp_hdr(struct tcphdr *tcph, struct bpf_tcp_conn *c, __u32 tgt_ts, void *data_end, __u16 flags,
    struct TCPBP *bp)
{
    __u32 tx_seq = bp->seq_num;
    __u32 rx_wnd = bp->rwnd_size;
    __u32 ack_seq = bp->ack_seq;
    __u32 ts_ecr = c->tx_next_ts;
    struct tcp_timestamp_opt *ts_opt = (struct tcp_timestamp_opt *)(tcph + 1);
    if (ts_opt + 1 > data_end) {
        return;
    }
    __u16 len = 5 + TS_OPT_SIZE / 4;
    /* fill tcp header */
    tcph->seq = bpf_htonl(tx_seq);
    tcph->ack_seq = bpf_htonl(ack_seq);
    
    set_tcp_flag(tcph, len, flags);
    tcph->ack = bp->is_ack;

    ts_opt->kind = TCPI_OPT_TIMESTAMPS;
    ts_opt->length = sizeof(*ts_opt) / 4;
    ts_opt->ts_val = bpf_htonl(tgt_ts);
    ts_opt->ts_ecr = bpf_htonl(ts_ecr);
    
    tcph->window = bpf_htons(rx_wnd) >> TCP_WND_SCALE;
    tcph->urg_ptr = 0;

    // Newer kernel has supported XDP_TXMD_FLAGS_CHECKSUM, ignore the overhead
    tcph->check = 0;
}

static __always_inline struct TCPBP send_ep
(struct app_timer_event *ev, struct bpf_tcp_conn *c, struct interm_out *int_out, struct meta_info *data_meta) {
    c->data_end += ev->data_size;

    struct TCPBP bp;
    bp.src_port = c->local_port;
    bp.dest_port = c->remote_port;
    bp.seq_num = c->tx_next_seq;
    bp.is_ack = false;

    // Question: should be values not specified in MTP be filled here with default values by the compiler?
    // For now, I'm filling with what they should have
    bp.ack_seq = c->rx_next_seq;
    bp.rwnd_size = c->rx_avail;

    c->tx_next_seq += ev->data_size;

    // TODO: add functions to initialize timers

    return bp;
}

static __always_inline struct app_timer_event parse_req_to_app_event(struct meta_info *data_meta) {
    struct app_timer_event ev;
    ev.type = APP_EVENT;
    // Question: this could work, but the thing is that this is target-specific, i.e.
    // it is a part of eTran's TX metadata. Also, it is the length for that batch of packets
    // (given the userspace window)
    // We may need to have a way to send the application and timer event to XDP_EGRESS without
    // using the metadata (how about some metadata after the payload?)
    ev.data_size = data_meta->tx.plen;
    return ev;
}

static __always_inline struct app_timer_event parse_req_to_timer_event(struct meta_info *data_meta) {
    struct app_timer_event ev;
    ev.type = TIMER_EVENT;
    // Question: what will be set here is also a bit complex.
    // What is in the timer event will be set and reset by EPs (send and ack), in addition to the
    // timer itself. Meanwhile, the control path will keep track of the timer. When the timer is
    // reached, it will need to send the timer event associated to that timer back here.
    // Does that make sense? I wonder if there might be situations where it might be problematic

    // ev.seq_num = data_meta->tx.;
    return ev;
}

static __always_inline struct net_event parse_pkt_to_event(struct tcphdr *tcph, struct iphdr *iph, struct tcp_timestamp_opt *ts_opt) {
    struct net_event ev;
    // 1 == NET_EVENT_ACK, 0 == NET_EVENT_DATA
    ev.minor_type = tcph->ack;
    ev.ack_seq = bpf_ntohl(tcph->ack_seq);
    ev.rwnd_size = bpf_ntohs(tcph->window);
    ev.seq_num = bpf_ntohl(tcph->seq);
    ev.data_len = bpf_ntohs(iph->tot_len) - (sizeof(struct iphdr) + sizeof(struct tcphdr) + TS_OPT_SIZE);
    ev.ecn_mark = tcph->ece;
    ev.ts_ecr = bpf_ntohl(ts_opt->ts_ecr);
    return ev;
}

// TODO: remove this tx_nump after the ACK chain is done
/*static __always_inline void fast_retr_rec_ep(struct net_event *ev, struct bpf_tcp_conn *c, struct interm_out *int_out, struct meta_info *data_meta,
    __u32 cpu, struct bpf_cc *cc) {
    //bpf_printk("%u %u %u", ev->ack_seq, c->send_una, c->tx_next_seq);
    //if(ev->ack_seq < c->send_una || c->tx_next_seq < ev->ack_seq) {
    //    int_out->skip_ack_eps = 1;
    //    return 0;
    //}
    int_out->drop = 1;

    // Question: in eTran the __u32-long values like tx_next_seq, send_una, etc, quickly
    // reach the limit of this size, which result in them requiring this part.
    // But in ours we didn't have something that complex. Are we doing something wrong?
    __u32 exp_ack_first = c->send_una;
    __u32 exp_ack_last = c->tx_next_seq;

    // allow receving ack that we haven't sent yet, this is probably caused by retransmission
    exp_ack_last += c->tx_pending;
    
    if (exp_ack_first <= exp_ack_last) {
        if (ev->ack_seq < exp_ack_first || ev->ack_seq > exp_ack_last) {
            bpf_printk("TESTE1");
            return;
        }

        // 0-----exp_ack_first-----ack_seq-----exp_ack_last-----__UINT32_MAX__
        int_out->num_acked_bytes = ev->ack_seq - exp_ack_first;
    } else {
        if (exp_ack_first > ev->ack_seq && ev->ack_seq > exp_ack_last) {
            bpf_printk("TESTE2");
            return;
        }
        // 0-----exp_ack_first-----------------exp_ack_first--ack_seq---__UINT32_MAX__
        // 0--ack_seq---exp_ack_first-----------------exp_ack_first-----__UINT32_MAX__
        int_out->num_acked_bytes = ev->ack_seq - exp_ack_first;
    }
    if(int_out->num_acked_bytes > c->tx_sent)
        bpf_printk("TESTE3");

    // Question: we need to have a way to differentiate context fields that are shared and those that aren't
    // between userspace and XDP (maybe those used in timer events?)
    cc->cnt_rx_ack_bytes += int_out->num_acked_bytes;
    if(ev->ecn_mark)
        cc->cnt_rx_ecn_bytes += int_out->num_acked_bytes;

    // Question: this field tx_sent is widely used in their code. Should we simply use it in MTP too?
    c->tx_sent -= int_out->num_acked_bytes;
    cc->txp = c->tx_sent > 0;

    int_out->change_cwnd = 1;

    __u32 go_back_bytes = 0;
    // Question: the way they do this check is a bit different.
    // It seems that they get the number of bytes acknowledged in the ack, and enter the condition if it's zero
    // Should we do the same?
    if(ev->ack_seq == c->last_ack) {
        int_out->change_cwnd = 0;
        c->rx_dupack_cnt += 1;
        if(c->rx_dupack_cnt == 3) {
            bpf_printk("AQUI CARALHO");
            // TODO: comment this one later after ack_net_ep is done (we only zero rx_dupack_cnt there in MTP)
            c->rx_dupack_cnt = 0;

            go_back_bytes = c->tx_next_seq - c->send_una;
            c->tx_next_seq -= go_back_bytes;
            if (c->tx_next_pos >= go_back_bytes) {
                c->tx_next_pos -= go_back_bytes;
            } else {
                c->tx_next_pos = c->tx_buf_size - (go_back_bytes - c->tx_next_pos);
            }

            // Question: this section of code isn't covered in MTP (is used by the other parts of the code)
            // If everything works out by adding our EPs, we can remove this part safely
            c->tx_pending = 0;
            c->rx_remote_avail += go_back_bytes;
            c->tx_sent = 0;
            cc->txp = 0;

            // Question: in eTran they don't decrease the DCTCP window both in fast retransmission and timeout.
            // They confirmed it is a bug.
            // Should we decrease the window here? But by how much, considering that the rate is cut by half
            // in their implementation?
            // But window will need to be shared with userspace too
            if(cc->cnt_tx_drops == 0) {
                cc->rate >>= 1;
                //cc->cwnd_size >>= 1;
            }

            cc->cnt_tx_drops++;
            // Question: in MTP we would have a set_rate function here.
            // But this rate would only be used in XDP_EGRESS and enqueueing the packets to the timing wheel
            // Can we consider the compiler would simply ignore the function?
        }
    } else {
        c->rx_dupack_cnt = 0;
        c->last_ack = ev->ack_seq;
    }

    int_out->go_back_bytes = go_back_bytes;
    c->send_una = ev->ack_seq;
}*/

static __always_inline __u32 fast_retr_rec_ep(struct net_event *ev, struct bpf_tcp_conn *c, struct interm_out *int_out, struct meta_info *data_meta,
    __u32 cpu, struct bpf_cc *cc, __u32 *tx_bump) {
    //bpf_printk("%u %u %u", ev->ack_seq, c->send_una, c->tx_next_seq);
    /*if(ev->ack_seq < c->send_una || c->tx_next_seq < ev->ack_seq) {
        int_out->skip_ack_eps = 1;
        return 0;
    }*/

    // Question: in eTran the __u32-long values like tx_next_seq, send_una, etc, quickly
    // reach the limit of this size, which result in them requiring this part.
    // But in ours we didn't have something that complex. Are we doing something wrong?
    __u32 exp_ack_first = c->send_una;
    __u32 exp_ack_last = c->tx_next_seq;

    // allow receving ack that we haven't sent yet, this is probably caused by retransmission
    exp_ack_last += c->tx_pending;
    
    if (exp_ack_first <= exp_ack_last) {
        if (ev->ack_seq < exp_ack_first || ev->ack_seq > exp_ack_last)
            return -1;

        // 0-----exp_ack_first-----ack_seq-----exp_ack_last-----__UINT32_MAX__
        *tx_bump = ev->ack_seq - exp_ack_first;
    } else {
        if (exp_ack_first > ev->ack_seq && ev->ack_seq > exp_ack_last)
            return -1;
        // 0-----exp_ack_first-----------------exp_ack_first--ack_seq---__UINT32_MAX__
        // 0--ack_seq---exp_ack_first-----------------exp_ack_first-----__UINT32_MAX__
        *tx_bump = ev->ack_seq - exp_ack_first;
    }

    __u32 num_acked_bytes = *tx_bump;
    // Question: we need to have a way to differentiate context fields that are shared and those that aren't
    // between userspace and XDP (maybe those used in timer events?)
    cc->cnt_rx_ack_bytes += num_acked_bytes;
    if(ev->ecn_mark)
        cc->cnt_rx_ecn_bytes += num_acked_bytes;

    // Question: this field tx_sent is widely used in their code. Should we simply use it in MTP too?
    c->tx_sent -= num_acked_bytes;
    cc->txp = c->tx_sent > 0;

    int_out->change_cwnd = 1;

    __u32 go_back_bytes = 0;
    // Question: the way they do this check is a bit different.
    // It seems that they get the number of bytes acknowledged in the ack, and enter the condition if it's zero
    // Should we do the same?
    if(ev->ack_seq == c->last_ack) {
        int_out->change_cwnd = 0;
        c->rx_dupack_cnt += 1;
        if(c->rx_dupack_cnt == 3) {
            // TODO: uncomment this one later after ack_net_ep is done (we only zero rx_dupack_cnt there in MTP)
            c->rx_dupack_cnt = 0;

            go_back_bytes = c->tx_next_seq - c->send_una;
            c->tx_next_seq -= go_back_bytes;
            if (c->tx_next_pos >= go_back_bytes) {
                c->tx_next_pos -= go_back_bytes;
            } else {
                c->tx_next_pos = c->tx_buf_size - (go_back_bytes - c->tx_next_pos);
            }

            // Question: this section of code isn't covered in MTP (is used by the other parts of the code)
            // If everything works out by adding our EPs, we can remove this part safely
            c->tx_pending = 0;
            c->rx_remote_avail += go_back_bytes;
            c->tx_sent = 0;
            cc->txp = 0;

            // Question: in eTran they don't decrease the DCTCP window both in fast retransmission and timeout.
            // They confirmed it is a bug.
            // Should we decrease the window here? But by how much, considering that the rate is cut by half
            // in their implementation?
            // But window will need to be shared with userspace too
            if(cc->cnt_tx_drops == 0) {
                cc->rate >>= 1;
                //cc->cwnd_size >>= 1;
            }

            cc->cnt_tx_drops++;
            // Question: in MTP we would have a set_rate function here.
            // But this rate would only be used in XDP_EGRESS and enqueueing the packets to the timing wheel
            // Can we consider the compiler would simply ignore the function?
        }
    } else {
        c->rx_dupack_cnt = 0;
        c->last_ack = ev->ack_seq;
    }
    /*---------------- VERY IMPORTANT TO REMEMBER ----------------*/
    /*---------------- VERY IMPORTANT TO REMEMBER ----------------*/
    /*---------------- VERY IMPORTANT TO REMEMBER ----------------*/
    // TODO: remove this when ack_net_ep is complete
    c->send_una = ev->ack_seq;
    return go_back_bytes;
    /*---------------- VERY IMPORTANT TO REMEMBER ----------------*/
    /*---------------- VERY IMPORTANT TO REMEMBER ----------------*/
    /*---------------- VERY IMPORTANT TO REMEMBER ----------------*/
}

static __always_inline void ack_net_ep(struct net_event *ev, struct bpf_tcp_conn *c, struct interm_out *int_out, struct meta_info *data_meta,
    __u32 cpu, struct bpf_cc *cc) {
    /*if(int_out->skip_ack_eps)
        return;
    bpf_printk("%d %d %d", ev->ack_seq, c->send_una, c->tx_next_seq);
    
    // Redirect it to userspace
    int_out->drop = 0;

    if(c->rx_dupack_cnt == 3) {
        c->rx_dupack_cnt = 0;
        // Question: this part is quite weird.
        // To notify the userspace to retransmit the packets (with go-back-N), eTran simply
        // marks the ACK packet with this flag and specify the number of bytes to go back
        // (with c->send_una, after it was decreased in fast_retransmit).
        // But how would the compiler be able to convert that whole pkt_bp creation,
        // pkt_gen_instr, and so on, into this?
        // This doesn't look very general, but in case a pkt_bp is generated in a
        // NET event EP for an unseg_data:
        // Maybe we can assume that rx.go_back_pos will be the second argument of the
        // fourth argument of unseg_data, specifying where the new seq_nums will start from.
        data_meta->rx.xsk_budget_avail = xsk_budget_avail(c);
        data_meta->rx.go_back_pos = int_out->go_back_bytes;
        data_meta->rx.go_back_pos |= RECOVERY_MASK;
        data_meta->rx.rx_pos = POISON_32;
        data_meta->rx.poff = POISON_16;
        data_meta->rx.plen = POISON_16;
        return;
    }

    // Question (not really):
    // Think about how we'll deal with the if(ctx.lwu_seq < ev.seq_num...) here, and so on
    // __u32 rwindow = ev->rwnd_size << TCP_WND_SCALE;
    c->rx_remote_avail = ev->rwnd_size << TCP_WND_SCALE;
        */
    // Question: same from MTP file. Do we have a function to get current timestamps in MTP?
    if(ev->ts_ecr && int_out->num_acked_bytes) {
        __u32 now = now = bpf_ktime_get_ns();
        __u32 rtt = (now - ev->ts_ecr);
        rtt /= 1000; // microseconds
        rtt -= (int_out->num_acked_bytes * 1000000) / LINK_BANDWIDTH;
        // bpf_printk("CPU#%u, RTT: %u us", bpf_get_smp_processor_id(), rtt);
        if (rtt < TCP_MAX_RTT) {
            if (cc->rtt_est)
                cc->rtt_est = (cc->rtt_est * 7 + rtt) / 8;
            else
                cc->rtt_est = rtt;
        }
    }

    // Question: eTran doesn't have a data_end value in the context.
    // This value represents the total amount of bytes to send (increased in the send EP).
    // Does it make sense to send the app_event as an element of the TX metadata, and use
    // it in the EP implemented in XDP_EGRESS? I think it makes sense
    // But the problem is that we cannot use the metadatas, because it seems that their
    // current metadata are already using the maximum size (32 bytes). So, we have the following options:
    // Use the current information that they have in the metadatas (they send the size of a batch). But this wouldn't be general
    // Repurpose their metadata. But that would probably break the whole eTran system (also, still limited with the 32 bytes)
    // Have another way to send this information. But it is probably hard to synchronize userspace and XDP_EGRESS?
    // A: I just added a data_end in the context and increase for each app_event from its data_len size.
    // This works because we're considering that each packet reaching XDP_EGRESS is a app event
    
    /*__u32 data_rest = c->data_end - c->tx_next_seq;
    if(data_rest == 0 && ev->ack_seq == c->tx_next_seq) {
        // Question: here we should have a function call to cancel the timer.
        // Probably set a boolean that is mmapped to control path, saying that the timer is cancelled
        // TODO: add cancel timer functions
        return;
    }*/

    // Question: in eTran they simply send number of ack_bytes to userspace
    // by redirecting it back as a metadata. It doesn't have something like the whole flush idea.
    // Maybe we can assume that the last argument of tx_data_flush will be used in rx.ack_bytes?
    /*__u32 rmlen = int_out->num_acked_bytes;
    if(rmlen > 0) {
        data_meta->rx.ack_bytes = rmlen;
        data_meta->rx.xsk_budget_avail = xsk_budget_avail(c);
        data_meta->rx.rx_pos = POISON_32;
        data_meta->rx.poff = POISON_16;
        data_meta->rx.plen = POISON_16;
        c->send_una = ev->ack_seq;
    }*/
    // TODO: add timer instruction to restart the timeout timer
}

#if 0
static __always_inline int app_ev_dispatcher(struct app_timer_event *ev, struct bpf_tcp_conn *c, struct meta_info *data_meta) {
    struct interm_out int_out;
    int_out.drop = 1;

    // TODO: implement the app EP, but (hopefully it will be the most straight to the point)
    return 0;
}


static __always_inline void ack_timeout_ep(struct net_event *ev, struct bpf_tcp_conn *c, struct interm_out *int_out, struct meta_info *data_meta) {
    // Halve rate
    c->rate >>= 1;
    // TODO: halve window too?
    //c->
    __u32 go_back_bytes = c->data_end - c->send_una;
    c->tx_next_seq -= go_back_bytes;

    // Question: to translate the unseg_data into this section of code, we would probably
    // need to just get the second argument and use it here.
    data_meta->rx.go_back_pos = go_back_bytes;
    // prepare to redirect to userspace
    data_meta->rx.qid = POISON_32;
    data_meta->rx.conn = c->opaque_connection;
    data_meta->rx.rx_pos = POISON_32;
    data_meta->rx.poff = POISON_16;
    data_meta->rx.plen = POISON_16;
    data_meta->rx.xsk_budget_avail = xsk_budget_avail(c);
    data_meta->rx.go_back_pos |= RECOVERY_MASK;
    data_meta->rx.ooo_bump = POISON_32;

    int_out->drop = 0;
}

static __always_inline int timer_ev_dispatcher(struct app_timer_event *ev, struct bpf_tcp_conn *c, struct meta_info *data_meta) {
    struct interm_out int_out;
    int_out.drop = 1;
    ack_timeout_ep(ev, c, &int_out, data_meta);

    return int_out.drop ? XDP_DROP : XDP_PASS;
}

static __always_inline void rto_ep(struct net_event *ev, struct bpf_tcp_conn *c, struct interm_out *int_out, struct meta_info *data_meta, __u32 cpu) {
    // Question: should we use their implementation of tcp_valid_ack?
    if(ev->ack_seq < c->send_una || c->tx_next_seq < ev->ack_seq) {
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

static __always_inline void slows_congc_ep(struct net_event *ev, struct bpf_tcp_conn *c, struct interm_out *int_out, struct meta_info *data_meta, __u32 cpu) {
    if(int_out->skip_ack_eps)
        return;
    
    if(int_out->change_cwnd) {
        // Question: the same from the MTP file.
        // In their implementation, they run slow start if the number of drops, packets with ECN, and retransmissions
        // is zero. Meanwhile, this decision is done in ours based on the congestion window size and ssthresh.
        // Which should we use?
        // Probably we cannot use their exact implementation here (since it is supposed to happen over intervals
        // in control path)

        // Question: in the control path, they have the DCTCP window, which is increased with SS or CA.
        // And, then, this window is converted into rate.
        // Is it possible for us to keep working only with rate (increasing and decreasing it)?
        // i.e. no need to keep a window and converting it
        // I don't think we can do that though
    }
}

static __always_inline int trim_and_handle_ooo(__u32 *seq, __u32 *payload_len, struct bpf_tcp_conn *c, struct meta_info *data_meta, struct interm_out *int_out, bool *clear_ooo) {
    __u32 rx_bump = 0;
    __u32 trim_start, trim_end;
    int_out->trigger_ack = true;
    // Question: in eTran, they do not generate an ACK if the seq num is invalid.
    // Should we do the same?
    if (unlikely(tcp_valid_rxseq_ooo(c, *seq, *payload_len, &trim_start, &trim_end))) {
        int_out->trigger_ack = false;
        //xdp_log_err("Bad seq");
        //goto unlock;
        return rx_bump;
    }
    __u32 payload_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + TS_OPT_SIZE;
    payload_off += trim_start;
    if (likely(*payload_len >= trim_start + trim_end))
        *payload_len -= trim_start + trim_end;
    data_meta->rx.poff = payload_off;
    data_meta->rx.plen = *payload_len;

    *seq += trim_start;
    data_meta->rx.rx_pos = c->rx_next_pos + (*seq - c->rx_next_seq);
    if (data_meta->rx.rx_pos >= c->rx_buf_size)
        data_meta->rx.rx_pos -= c->rx_buf_size;

    /* check if we can add it to the out of order interval */
    if (unlikely(*seq != c->rx_next_seq)) {
        if (!*payload_len) return rx_bump;
        xdp_log("OOO packet, seq(%u), c->rx_next_seq(%u)", *seq, c->rx_next_seq);
        if (c->rx_ooo_len == 0) {
            c->rx_ooo_start = *seq;
            c->rx_ooo_len = *payload_len;
            xdp_log("New segment, ooo_start(%u), ooo_len(%u)", c->rx_ooo_start, c->rx_ooo_len);
        } else if (*seq + *payload_len == c->rx_ooo_start) {
            c->rx_ooo_start = *seq;
            c->rx_ooo_len += *payload_len;
            xdp_log("Merge segment, ooo_start(%u), ooo_len(%u)", c->rx_ooo_start, c->rx_ooo_len);
        } else if (c->rx_ooo_start + c->rx_ooo_len == *seq) {
            c->rx_ooo_len += *payload_len;
            xdp_log("Merge segment, ooo_start(%u), ooo_len(%u)", c->rx_ooo_start, c->rx_ooo_len);
        } else {
            // unfortunately, we can't accept this payload
            *payload_len = 0;
            data_meta->rx.plen = POISON_16;
            xdp_log("Drop packet, ooo_start(%u), ooo_len(%u)", c->rx_ooo_start, c->rx_ooo_len);
        }
        // mark this packet is an out-of-order segment
        data_meta->rx.ooo_bump = OOO_SEGMENT_MASK;

        //goto unlock;
    }

    /* update TCP state if we have payload */
    if (likely(*payload_len)) {
        rx_bump = *payload_len;
        c->rx_avail -= *payload_len;
        c->rx_next_pos += *payload_len;
        if (c->rx_next_pos >= c->rx_buf_size)
            c->rx_next_pos -= c->rx_buf_size;
        c->rx_next_seq += *payload_len;

        // xdp_log("seq(%u), payload_len(%u), c->rx_avail(%u), c->rx_next_pos(%u), c->rx_next_seq(%u)", seq, *payload_len, c->rx_avail, c->rx_next_pos, c->rx_next_seq);
        
        /* handle existing out-of-order segments */
        if (unlikely(c->rx_ooo_len)) {
            if (tcp_valid_rxseq_ooo(c, c->rx_ooo_start, c->rx_ooo_len, &trim_start, &trim_end)) {
                /* completely superfluous: drop out of order interval */
                c->rx_ooo_len = 0;
                data_meta->rx.ooo_bump = OOO_CLEAR_MASK;
                int_out->trigger_ack = false;
                *clear_ooo = true;
            } else {
                c->rx_ooo_start += trim_start;
                c->rx_ooo_len -= trim_start + trim_end;

                // accept out-of-order segments
                if (c->rx_ooo_len && c->rx_ooo_start == c->rx_next_seq) {
                    xdp_log("c->rx_ooo_len(%u), c->rx_ooo_start(%u), c->rx_next_seq(%u)", c->rx_ooo_len, c->rx_ooo_start, c->rx_next_seq);
                    rx_bump += c->rx_ooo_len;
                    c->rx_avail -= c->rx_ooo_len;
                    c->rx_next_pos += c->rx_ooo_len;
                    if (c->rx_next_pos >= c->rx_buf_size)
                        c->rx_next_pos -= c->rx_buf_size;
                    c->rx_next_seq += c->rx_ooo_len;

                    c->rx_ooo_len = 0;
                    // out-of-order segment is processed
                    data_meta->rx.ooo_bump = OOO_FIN_MASK;
                    xdp_log("Out-of-order segment is processed");
                }
            }
        }

        if (unlikely((c->rx_avail >> TCP_WND_SCALE) == 0)) {
            // ebpf realized that the receive buffer is empty,
            // piggyback a signal to lib, once application releases the buffer, force it sync with us
            data_meta->rx.qid |= FORCE_RX_BUMP_MASK;
            // bpf_printk("force");
        }
        // bpf_printk("c->rx_avail = %u", c->rx_avail);
    }
    return rx_bump;
}

static __always_inline void data_net_ep(struct net_event *ev, struct bpf_tcp_conn *c, struct interm_out *int_out, struct meta_info *data_meta, __u32 cpu) {

    // Maybe remove this one if we simply use eTran's solution
    if((c->rx_avail == 0 && ev->data_len > 0) ||
       (ev->seq_num > c->rx_next_seq + c->rx_avail) ||
       (ev->seq_num + ev->data_len - 1 < c->rx_next_seq)) {
        return;
    }

    // Question: the same as in the MTP file.
    // eTran has a function that checks if an ack is valid and out-of-order (tcp_valid_rxseq_ooo)
    // Should we use the same function as they use to do that?
    // Also, different to ours approach, it seems that they keep track of only one interval of OOO sequence numbers
    // For example, if X is a sequence number that arrived and _ is a missing sequence number, this situation:
    // ___XXXX____XXXX____
    // Wouldn't be possible, because it seems that they only support one interval of OOO sequence numbers, like:
    // ___XXXXXXXX____
    // Should we do the same, then? (not use the sliding window idea we have in MTP)
    // For, now, I'll use their implementation, assuming that the set and first_unset sliding
    // window methods can be translated as this function call:

    __u32 seq = ev->seq_num;
    __u32 payload_len = ev->data_len;

    // Question: following the idea presented above, I chose to have a function containing
    // their code that handles payload triming and OOO handling.
    // But the problem is that they do operations over c->rx_next_seq and c->rx_avail.
    // For c->rx_next_seq, which is the next sequence number expected to recv (equivalent to our ctx.recv_next),
    // they kind of consider that their "sliding window" start from it, using it to see if the payload
    // is valid an OOO. However, in MTP we do not pass anything like that in the set method. What should we do
    // in this case?
    // At least, we can update c->rx_next_seq by (instead of doing in the function) making it return the desired
    // value and then updating it here (same for c->rx_avail). But the problem still remains regarding using
    // this value in the function.
    // And for c->rx_avail, which is the number of bytes available to recv (they treat it as the recv window size),
    // we do not change its in our code (it is constant). Meanwhile, in eTran they change it. What should we do here?

    bool clear_ooo = false;
    __u32 rx_bump = trim_and_handle_ooo(&seq, &payload_len, c, data_meta, int_out, &clear_ooo);

    // Question: maybe we'll need to use TCP_LOCK across the code.
    // It seems that this lock is used to access the context c, and it is acquired/released
    // by the different XDP programs. So, they can run in parallel? It seems so
    // The problem is where to put the locks. They put at the start of the tcp process functions
    // and the function that enqueues ACKs.
    // Maybe we simply add at the start of net_ev_dispatcher and the app dispatcher (if there is one)?

    // Question: I wonder if add_data_seg could be translated the section below.
    // ev.data_len would be converted to payload_len and the rest wouldn't
    // matter or data_meta would be filled already in the function above (like the offset (last arg) and rx.poff)
    if(rx_bump || clear_ooo) {
        int_out->drop = 0;
        data_meta->rx.xsk_budget_avail = xsk_budget_avail(c);
        xdp_log("xsk_budget_avail(%u)", data_meta->rx.xsk_budget_avail);
        /*if (tx_bump)
            data_meta->rx.ack_bytes = tx_bump;
        else if (unlikely(go_back_pos)) {
            xdp_log("go_back_pos(%u)", go_back_pos);
            data_meta->rx.go_back_pos = go_back_pos;
            data_meta->rx.go_back_pos |= RECOVERY_MASK;
        }*/

        if (!payload_len) {
            data_meta->rx.rx_pos = POISON_32;
            data_meta->rx.poff = POISON_16;
            data_meta->rx.plen = POISON_16;
            //goto out;
        } else if (unlikely(data_meta->rx.ooo_bump & OOO_FIN_MASK)) {
            /* piggyback rx_bump */
            data_meta->rx.ooo_bump |= rx_bump;
        }
    }
}

static __always_inline void send_ack(struct net_event *ev, struct bpf_tcp_conn *c, struct interm_out *int_out, struct meta_info *data_meta, __u32 cpu) {
    if(!int_out->trigger_ack) {
        return;
    }
    
    // Question: eTran has two ways to generate ACKs. One ACK per arriving packet and
    // ACK coalescing. It seems that they use ACK coalescing by default.
    // On one hand, using ACK coalescing might be useful to compare with an "optimized" eTran,
    // and might also be useful to see how that can be implemented in MTP.
    // However, the way they trigger the ACK enqueue is a bit different from our approach.
    // An ACK is enqueued if: the current packet's flow is different from the last, which
    // results in enqueueing values from the previous packet's context; or if XDP_GEN runs,
    // meaning a NAPI batch is finished.
    // But how can we represent these ideas in MTP? Storing flow IDs between packets may be
    // a bit contrived, and I think that the context wouldn't serve for that, since it's per-flow.
    // And MTP won't have a way to understand a NAPI batch.

    // Looks to me that using the per-packet ACK would better match what we have and,
    // probably, MTP. I'll be following this approach for now

    struct bpf_tcp_ack *ack = NULL;
    __u32 prod = ack_prod[cpu];
    __u32 cons = ack_cons[cpu];

    // check if ack queue is full
    if (unlikely(cons == ((prod + 1) & (NAPI_BATCH_SIZE - 1)))) {
        xdp_log_err("ack queue is full");
    } else {
        ack = bpf_map_lookup_elem(&bpf_tcp_ack_map, &prod);
        if (unlikely(!ack))
            xdp_log_err("ack is NULL");
    }

    ack->local_ip = c->local_ip;
    ack->remote_ip = c->remote_ip;
    ack->local_port = c->local_port;
    ack->remote_port = c->remote_port;
    ack->seq = c->tx_next_seq;
    ack->ack = c->rx_next_seq;
    ack->rxwnd = c->rx_avail;
    ack->is_ack = 1;
    // Question: similar to other questions, should we add these timestamps?
    // It seems that they are used to calculate the RTT. In our implementation, we consider it a constant
    /*ack->ts_val = now;
    ack->ts_ecr = c->tx_next_ts;
    c->tx_next_ts = 0;*/

    ack_prod[cpu] = (ack_prod[cpu] + 1) & (NAPI_BATCH_SIZE - 1);
}

// Question: do we need to have a scheduler in eTran?
// I guess that the only queue that we could have would be timer, but I'm not sure if that
// would be necessary

static __always_inline int net_ev_dispatcher(struct net_event *ev, struct bpf_tcp_conn *c, struct meta_info *data_meta, __u32 cpu) {
    struct interm_out int_out;
    int_out.drop = 1;
    if(ev->minor_type == NET_EVENT_ACK) {
        rto_ep(ev, c, &int_out, data_meta, cpu);
        fast_retr_rec_ep(ev, c, &int_out, data_meta, cpu);
        slows_congc_ep(ev, c, &int_out, data_meta, cpu);
        ack_net_ep(ev, c, &int_out, data_meta, cpu);
    } else if (ev->minor_type == NET_EVENT_DATA) {
        data_net_ep(ev, c, &int_out, data_meta, cpu);
        send_ack(ev, c, &int_out, data_meta, cpu);
    }
    return int_out.drop ? XDP_DROP : XDP_REDIRECT;
}
#endif