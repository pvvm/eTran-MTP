#ifndef MTP_DEFS_H
#define MTP_DEFS_H

// Comment this to turn off MTP functions
#define MTP_ON 1

#define NET_EVENT_ACK 1
#define NET_EVENT_DATA 0

#define APP_EVENT 1
#define TIMER_EVENT 0

struct TCPBP {
    __u16 src_port;
    __u16 dest_port;
    __u32 seq_num;
    __u32 ack_seq;
    bool is_ack;
    __u16 rwnd_size;
};

struct interm_out {
    __u8 change_cwnd;
    __u8 skip_ack_eps;
    __u8 trigger_ack;
    __u8 drop;
    __u32 num_acked_bytes;
    __u32 go_back_pos;
};

// Represents APP and TIMER events in XDP
struct app_timer_event {
    __u8 type;
    // APP fields
    __u32 data_size;

    // TIMER fields
    __u32 seq_num;
};
struct net_event {
    __u8 minor_type;
    // ACK
    __u32 ack_seq;
    __u32 rwnd_size;
    __u32 ts_ecr;

    // DATA
    // Question: how are we representing hold_addr?
    __u32 data_len;

    // SHARED
    __u32 seq_num;
    bool ecn_mark;
};

#endif