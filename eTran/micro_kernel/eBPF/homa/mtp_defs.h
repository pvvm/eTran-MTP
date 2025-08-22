//#define MTP_ON 1

struct app_event {
    __u32 local_ip;
    __u32 remote_ip;
    __u32 msg_len;
    __u64 addr;
    __u16 src_port;
    __u16 dest_port;
    __u64 rpcid;
};

struct HOMA_ACK {
    __u64 rpcid;
    __u16 sport;
    __u16 dport;
};

struct DATA_SEG {
    __u32 offset;
    __u32 segment_length;
    struct HOMA_ACK ack;
};

struct DATA_HDR {
    __u32 message_length;
    __u32 incoming;
    __u16 cutoff_version;
    __u8 retransmit;
    struct DATA_SEG seg;
};

struct COMMON_HDR {
    __u32 src_port;
    __u32 dest_port;
    __u8 doff;
    __u8 type;
    __u16 seq;
    __u64 sender_id;
};

struct HOMABP {
    struct COMMON_HDR common;
    struct DATA_HDR data;
};