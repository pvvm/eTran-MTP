#ifndef MTP_DEFS_H
#define MTP_DEFS_H

#define NET_EVENT_ACK 1
#define NET_EVENT_DATA 0

struct net_event {
    __u8 minor_type;
    // ACK
    __u32 ack_seq;
    __u32 rwnd_size;

    // DATA
    // Question: how are we representing hold_addr?
    __u32 data_len;

    // SHARED
    __u32 seq_num;
};

#endif