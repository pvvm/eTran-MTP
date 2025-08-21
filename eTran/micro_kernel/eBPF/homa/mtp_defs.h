#define MTP_ON 1

struct app_event {
    __u32 local_ip;
    __u32 remote_ip;
    __u32 msg_len;
    __u64 addr;
    __u16 src_port;
    __u16 dest_port;
    __u64 rpcid;
};

struct HOMABP {
    __u8 teste;
};