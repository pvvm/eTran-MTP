#pragma once

#include <stdio.h>
#include <arpa/inet.h> 
#include <netinet/ip.h>
#include <net/ethernet.h> 
#include <netinet/tcp.h>

void parse_packet(char *pkt) {
    struct tcphdr *tcp_header = (struct tcphdr *)(pkt + sizeof(struct ethhdr) + sizeof(struct iphdr));
    uint32_t seq_num = ntohl(tcp_header->seq);
    printf("%u\n", seq_num);
}