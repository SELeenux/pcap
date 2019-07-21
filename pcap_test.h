#ifndef MY_PCAP_H
#define MY_PCAP_H

#include <arpa/inet.h>

struct packet_eth{
    uint8_t d_mac[6];
    uint8_t s_mac[6];
    uint16_t Etype;
};

struct packet_ip{
    uint8_t ver_len;
    uint8_t tos;
    uint16_t len;
    uint16_t id;
    uint16_t offset;
    uint8_t ttl;
    uint8_t prt;
    uint16_t cks;
    uint8_t s_ip[4];
    uint8_t d_ip[4];
};

struct packet_tcp{
    uint16_t s_port;
    uint16_t d_port;
    uint32_t sqc;
    uint32_t ack;
    uint8_t len_r;
};


#endif
