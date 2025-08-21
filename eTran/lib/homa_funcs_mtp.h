#pragma once
#ifndef HOMA_FUNCS_MTP_H
#define HOMA_FUNCS_MTP_H

#include <stdio.h>
#include <eTran_rpc.h>


#define MTP_ON 1

void RpcSocket::parse_app_request(struct app_event *ev, uint32_t local_ip, uint32_t remote_ip, uint16_t src_port,
    uint16_t dest_port, uint32_t msg_len, uint64_t addr, uint64_t rpcid) {
    ev->local_ip = local_ip;
    ev->remote_ip = remote_ip;
    ev->src_port = src_port;
    ev->dest_port = dest_port;
    ev->msg_len = msg_len;
    ev->addr = addr;
    ev->rpcid = rpcid;
}

void RpcSocket::create_pkt_bp() {
    /*struct iphdr *iph = reinterpret_cast<struct iphdr *>(pkt + sizeof(struct ethhdr));
    iph->saddr = _local_addr.sin_addr.s_addr;
    iph->daddr = dest_addr->sin_addr.s_addr;
    iph->protocol = IPPROTO_HOMA;

    struct data_header *d = reinterpret_cast<struct data_header *>(pkt + sizeof(struct ethhdr) + sizeof(struct iphdr));
    d->common.sport = __cpu_to_be16(_local_port);
    d->common.dport = dest_addr->sin_port;
    d->common.doff = (sizeof(struct data_header) - sizeof(struct data_segment)) >> 2;
    d->common.type = DATA;
    d->common.seq = __cpu_to_be16(req_meta->seq);
    req_meta->seq++;
    d->common.sender_id = __cpu_to_be64(req_meta->rpcid);

    d->message_length = __cpu_to_be32(message_length);
    d->retransmit = 0;

    d->unused1 = slot_idx;

    d->incoming = 0;
    d->cutoff_version = 0;
    
    plen = std::min((size_t)HOMA_MSS, size);
    
    d->seg.offset = __cpu_to_be32(copy_offset);
    d->seg.segment_length = __cpu_to_be32(plen);
    d->seg.ack.rpcid = 0;
    d->seg.ack.dport = 0;
    d->seg.ack.sport = 0;*/
}

#endif