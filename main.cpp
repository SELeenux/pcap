#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "pcap_test.h"

#define SIZE_ETHERNET 14
#define IP_Header_LEN 20
#define TCP_Header_LEN 20

void print_mac(uint8_t const* mac){
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(uint8_t const* ip){
    printf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
}

void print_port(uint16_t const port){
    uint16_t tmp;
    tmp = ntohs(port);
    printf("%u", tmp);
}

void print_payload(u_char const* data){
    int i;
    printf("\n");
    for(i=0; i<10; i++){
        printf("%02x ", data[i]);
    }
    printf("\n\n");

}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {

  const struct packet_eth* eth;
  const struct packet_ip* ip;
  const struct packet_tcp* tcp;
  const u_char* payload;

  uint32_t ip_size;
  uint32_t tcp_size;
  uint32_t payload_size;

  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

//eth.dmac, eth.smac / ip.sip, ip.dip / tcp.sport, tcp.dport / data(10byte)
  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    eth = (struct packet_eth *)(packet);

    ip = (struct packet_ip *)(packet + SIZE_ETHERNET);
    ip_size = (ip->ver_len & 0x0F) * 4;
    if(ip_size < 20) continue;
    if(ip->prt != 6) continue;

    tcp = (struct packet_tcp *)(packet + SIZE_ETHERNET + ip_size);
    tcp_size = ((tcp->len_r & 0xF0) >> 4) * 4;
    if(tcp_size < 20) continue;

    payload_size = ntohs(ip->len) - ip_size - tcp_size;
    payload = (u_char *)(packet + SIZE_ETHERNET + ip_size + tcp_size);

    printf("==================================================\n");
    printf("d_mac ");
    print_mac(eth->d_mac);
    printf(" - s_mac ");
    print_mac(eth->s_mac);

    printf("\ns_ip ");
    print_ip(ip->s_ip);
    printf(" - d_ip ");
    print_ip(ip->d_ip);

    printf("\ns_port ");
    print_port(tcp->s_port);
    printf(" - d_port ");
    print_port(tcp->d_port);

    if(payload_size == 0) {printf("\nno payload!!\n"); continue;}
    print_payload(payload);
  }

  pcap_close(handle);
  return 0;
}
