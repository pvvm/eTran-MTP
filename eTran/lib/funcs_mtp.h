#pragma once

#include <stdio.h>
#include <arpa/inet.h> 
#include <netinet/ip.h>
#include <net/ethernet.h> 
#include <netinet/tcp.h>
#include "include/xsk_if.h"

#define MTP_ON 1

#define TS_OPT_SIZE 12
#define HEADERS_LEN (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + TS_OPT_SIZE)

static inline void in_order_receive(struct eTrantcp_connection *conn, uint64_t addr, char *pkt);

static inline void out_of_order_receive(struct eTrantcp_connection *conn, uint64_t addr, char *pkt);

void parse_packet(char *pkt, unsigned int *start_seq, unsigned int *end_seq, unsigned int py_len) {
    //struct iphdr *ip_header = (struct iphdr *)(pkt + sizeof(struct ethhdr));
    struct tcphdr *tcp_header = (struct tcphdr *)(pkt + sizeof(struct ethhdr) + sizeof(struct iphdr));
    //uint32_t length = ntohs(ip_header->tot_len) - (sizeof(struct iphdr) + sizeof(struct tcphdr) + TS_OPT_SIZE);
    uint32_t seq_num = ntohl(tcp_header->seq);
    uint16_t py_off = rxmeta_poff(pkt);
    //uint32_t rx_pos = rxmeta_pos(pkt);
    //printf("Curr: %u\tNext: %u\n", seq_num, seq_num + length);
    //printf("py_len: %u\tpy_off: %u\trx_pos: %u\n", py_len, py_off, rx_pos);

    *start_seq = seq_num + (py_off - HEADERS_LEN);
    *end_seq = seq_num + py_len;
    //printf("Trimmed start seq: %u\tTrimmed end seq: %u\n", *start_seq, *end_seq);
}

void mtp_add_data_seg_wrapper(struct app_ctx_per_thread *tctx, char *pkt, unsigned int start_seq,
    unsigned int end_seq, unsigned int py_len, struct eTrantcp_connection *conn, uint64_t addr,
    size_t *cached_rx_bump, uint32_t offset) {
    // If it is the first packet
    if(!tctx->following_packets) {
        *cached_rx_bump += py_len;
        in_order_receive(conn, addr, pkt);
        tctx->expected_seq = end_seq;
        tctx->following_packets = true;

        // For now, I'm considering that rx_buf_size will be this constant
        // Although that can change in parse_mc_args in micro_kernel.cc
        tctx->rx_buf_size = 524288;
        tctx->last_offset = offset;
        // It will always be tctx->rx_next_pos
        uint32_t rx_pos = tctx->rx_next_pos + (offset - tctx->last_offset);
        // Just in case
        if(rx_pos >= tctx->rx_buf_size) {
            rx_pos -= tctx->rx_buf_size;
        }
        rxmeta_set_pos(pkt, rx_pos);
        //printf("A: %u\n", rx_pos);
    } else {
        // If this packet is in order
        if(tctx->expected_seq == start_seq) {
            // If this packet is the last missing to reach the OOO sequence
            if(tctx->ooo_len > 0 && end_seq == tctx->ooo_start) {
                *cached_rx_bump += (py_len + tctx->ooo_len);
                /* append ooo_rx_addrs to the tail of rx_addrs */
                conn->rx_addrs.insert(conn->rx_addrs.end(), conn->ooo_rx_addrs.begin(), conn->ooo_rx_addrs.end());
                conn->ooo_rx_addrs.clear();

                uint32_t rx_pos = tctx->rx_next_pos + (offset - tctx->last_offset);
                if(rx_pos >= tctx->rx_buf_size) {
                    rx_pos -= tctx->rx_buf_size;
                }
                rxmeta_set_pos(pkt, rx_pos);
                //printf("B: %u\n", rx_pos);
                tctx->last_offset = offset;
                tctx->rx_next_pos += (py_len + tctx->ooo_len);
                if(tctx->rx_next_pos >= tctx->rx_buf_size) {
                    tctx->rx_next_pos -= tctx->rx_buf_size;
                }

                in_order_receive(conn, addr, pkt);
                tctx->expected_seq = tctx->ooo_start + tctx->ooo_len;
                tctx->ooo_len = 0;
            // If this packet is in order and does not complete a OOO sequence
            } else {
                tctx->expected_seq += py_len;
                *cached_rx_bump += py_len;

                uint32_t rx_pos = tctx->rx_next_pos + (offset - tctx->last_offset);
                if(rx_pos >= tctx->rx_buf_size) {
                    rx_pos -= tctx->rx_buf_size;
                }
                rxmeta_set_pos(pkt, rx_pos);
                //printf("C: %u\n", rx_pos);
                tctx->last_offset = offset;

                tctx->rx_next_pos += py_len;
                if(tctx->rx_next_pos >= tctx->rx_buf_size) {
                    tctx->rx_next_pos -= tctx->rx_buf_size;
                }

                in_order_receive(conn, addr, pkt);
            }
        
        // If this packet is OOO
        } else {
            if(tctx->ooo_len == 0) {
                tctx->ooo_start = start_seq;
                tctx->ooo_len = py_len;
            } else if(end_seq == tctx->ooo_start) {
                tctx->ooo_start = start_seq;
                tctx->ooo_len += py_len;
            } else if(tctx->ooo_start + tctx->ooo_len == start_seq){
                tctx->ooo_len += py_len;
            } else {
                return;
            }

            uint32_t rx_pos = tctx->rx_next_pos + (offset - tctx->last_offset);
            if(rx_pos >= tctx->rx_buf_size) {
                rx_pos -= tctx->rx_buf_size;
            }
            rxmeta_set_pos(pkt, rx_pos);
            //printf("D: %u\n", rx_pos);
            //tctx->last_offset = offset;

            out_of_order_receive(conn, addr, pkt);
        }
    }
}