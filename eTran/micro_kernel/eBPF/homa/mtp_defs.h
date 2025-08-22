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

static __always_inline
int send_req_ep_cient(struct iphdr *iph, struct app_event *ev, 
    struct HOMABP *bp, struct rpc_state *ctx,
    __u64 *rpc_qid, bool *trigger)
{
    struct rpc_state_cc *cc_node = NULL;
    struct rpc_state_cc *ref_cc_node = NULL;

    bool first_packet = bpf_ntohs(bp->common.seq) == 0 ? 1 : 0;
    __u32 message_length = bpf_ntohl(bp->data.message_length);
    __u32 offset = bpf_ntohl(bp->data.seg.offset);
    __u32 packet_bytes = bpf_ntohl(bp->data.seg.segment_length);
    bool single_packet = message_length <= HOMA_MSS;
    
    if (first_packet) {
        /* create a new RPC state */
        ctx->state = BPF_RPC_OUTGOING;
        ctx->message_length = message_length;
        ctx->next_xmit_offset = packet_bytes;
        ctx->buffer_head = ev->addr;
        ctx->remote_port = bpf_ntohs(bp->common.dest_port);
        ctx->local_port = bpf_ntohs(bp->common.src_port);
        ctx->remote_ip = bpf_ntohl(iph->daddr);
        ctx->id = bpf_be64_to_cpu(bp->common.sender_id);
        ctx->cc.granted = min(message_length, Homa_unsched_bytes);
        ctx->qid = MAX_BUCKET_SIZE;

        /* optimization for single-packet case */
        if (likely(single_packet)) {
            set_prio(iph, HOMA_MAX_PRIORITY - 1);
            bp->data.incoming = bpf_htonl(message_length);
            return XDP_TX;
        }
    }

    if (offset + packet_bytes < Homa_unsched_bytes)
        set_prio(iph, get_prio(message_length));
    else
        set_prio(iph, atomic_read(&ctx->cc.sched_prio));

    /* check if we have enough credit */
    __u64 cc_granted = atomic_read(&ctx->cc.granted);
    bp->data.incoming = bpf_htonl(cc_granted);

    if (offset + packet_bytes <= cc_granted) {
        /* we have enough credit, further check three conditions to determine if we can send packet directly 
         * 1) no packets in rate limiter
         * 2) packet size is small enough or NIC queue is not busy
         */
        if (atomic_read(&ctx->nr_pkts_in_rl) == 0 &&
            (packet_bytes <= Homa_min_throttled_bytes || check_nic_queue(packet_bytes)))
        {
            /* this update is safe for no packets in rate limiter */
            ctx->next_xmit_offset = offset + packet_bytes;
            return XDP_TX;
        }
    }

    /* Unfortunately, we should enqueue this packet to rate limiter */
    atomic_inc(&ctx->nr_pkts_in_rl);

    if (unlikely(ctx->qid == MAX_BUCKET_SIZE))
    {
        /* this RPC has not been enqueued before */
        ctx->qid = allocate_qid();
        CHECK_AND_DROP_LOG(ctx->qid == MAX_BUCKET_SIZE, "client_request, allocate_qid failed.");

        /* we create the qid, so we need to create an object and enqueue it to throttle list */
        cc_node = bpf_obj_new(typeof(*cc_node));
        CHECK_AND_DROP_LOG(!cc_node, "client_request, bpf_obj_new failed.");
        
        cc_node->birth = bpf_ktime_get_ns();
        cc_node->hkey.rpcid = ctx->id;
        cc_node->hkey.local_port = ctx->local_port;
        cc_node->hkey.remote_ip = ctx->remote_ip;
        cc_node->hkey.remote_port = ctx->remote_port;
        cc_node->bytes_remaining = ctx->message_length - ctx->next_xmit_offset;
        ref_cc_node = bpf_refcount_acquire(cc_node);
        CHECK_AND_DROP_LOG(!ref_cc_node, "client_request, bpf_refcount_acquire failed.");

        THROTTLE_LOCK();
        
        /* insert ref pointer to throttle list */
        bpf_rbtree_add(&troot, &ref_cc_node->rbtree_link, srpt_less_pacer);
        atomic_inc(&nr_rpc_in_throttle);
        
        THROTTLE_UNLOCK();

        /* store pointer in map for future update */
        PUT_POINTER(cc_node, ctx);
    }
    
    *rpc_qid = ctx->qid;


    // TODO: understand why this is problematic
    #if 0
    *trigger = cc_granted >= (offset + packet_bytes);

    #endif

    return XDP_REDIRECT;
}

static __always_inline
int send_resp_ep_server(struct iphdr *iph, struct app_event *ev, 
    struct HOMABP *bp, struct rpc_state *ctx,
    __u64 *rpc_qid, bool *trigger)
{

}