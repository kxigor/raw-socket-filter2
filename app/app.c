#include <arpa/inet.h>
#include <linux/version.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <string.h>

#include "include/raw_socket_forwarder.h"

#define TRIGGER_IP "162.252.205.131"
#define FAKE_NET_PREFIX "11.22.33."
#define MAX_HOPS 30

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
#define UDP_SOURCE(udp) ((udp)->uh_sport)
#define UDP_DEST(udp) ((udp)->uh_dport)
#define UDP_LEN(udp) ((udp)->uh_ulen)
#define UDP_CHECK(udp) ((udp)->uh_sum)
#else
#define UDP_SOURCE(udp) ((udp)->source)
#define UDP_DEST(udp) ((udp)->dest)
#define UDP_LEN(udp) ((udp)->len)
#define UDP_CHECK(udp) ((udp)->check)
#endif

uint16_t compute_checksum(uint16_t* addr, int len) {
  int count = len;
  uint32_t sum = 0;
  uint16_t answer = 0;

  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  if (count > 0) {
    sum += *(uint8_t*)addr;
  }

  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  answer = ~sum;
  return answer;
}

const char* bad_horse_names[] = {"bad.horse",
                                 "bad.horse",
                                 "bad.horse",
                                 "he.rides.across.the.nation",
                                 "the.thoroughbred.of.sin",
                                 "he.got.the.application",
                                 "that.you.just.sent.in",
                                 "it.needs.evaluation",
                                 "so.let.the.games.begin",
                                 "a.heinous.crime",
                                 "a.show.of.force",
                                 "a.murder.would.be.nice.of.course",
                                 "bad.horse",
                                 "bad.horse",
                                 "bad.horse",
                                 "he-s.bad",
                                 "the.evil.league.of.evil",
                                 "is.watching.so.beware",
                                 "the.grade.that.you.receive",
                                 "will.be.your.last.we.swear",
                                 "so.make.the.bad.horse.gleeful",
                                 "or.he-ll.make.you.his.mare",
                                 "o_o",
                                 "you-re.saddled.up",
                                 "there-s.no.recourse",
                                 "it-s.hi-ho.silver",
                                 "signed.bad.horse"};

// Простая функция для кодирования доменного имени в DNS формат
void encode_dns_name(char* dest, const char* src) {
  char* p = dest;
  char* start = p;
  int len = 0;

  while (*src) {
    if (*src == '.') {
      *start = len;
      start = p;
      len = 0;
    } else {
      *p = *src;
      len++;
    }
    p++;
    src++;
  }
  *start = len;
  *p = '\0';
}

Packet create_simple_dns_response(Packet input) {
  static int name_index = 0;

  Packet response;
  response.size = input.size + 100;
  response.buffer = malloc(response.size);
  memcpy(response.buffer, input.buffer, input.size);

  struct iphdr* ip = (struct iphdr*)(response.buffer + sizeof(struct ethhdr));
  uint32_t tmp_ip = ip->saddr;
  ip->saddr = ip->daddr;
  ip->daddr = tmp_ip;

  struct udphdr* udp =
      (struct udphdr*)(response.buffer + sizeof(struct ethhdr) +
                       sizeof(struct iphdr));
  uint16_t tmp_port = UDP_SOURCE(udp);
  UDP_SOURCE(udp) = UDP_DEST(udp);
  UDP_DEST(udp) = tmp_port;

  char* dns_data = (char*)(response.buffer + sizeof(struct ethhdr) +
                           sizeof(struct iphdr) + sizeof(struct udphdr));

  uint16_t* dns_flags = (uint16_t*)(dns_data + 2);
  *dns_flags = htons(0x8180);

  uint16_t* dns_answers = (uint16_t*)(dns_data + 6);
  *dns_answers = htons(1);

  char* answer_ptr = dns_data + 12;

  while (*answer_ptr != 0 &&
         (answer_ptr - dns_data) <
             (input.size - sizeof(struct ethhdr) - sizeof(struct iphdr) -
              sizeof(struct udphdr))) {
    answer_ptr++;
  }
  answer_ptr++;

  answer_ptr += 4;

  *(uint16_t*)answer_ptr = htons(0xC00C);
  answer_ptr += 2;

  *(uint16_t*)answer_ptr = htons(12);
  answer_ptr += 2;

  *(uint16_t*)answer_ptr = htons(1);
  answer_ptr += 2;

  *(uint32_t*)answer_ptr = htonl(300);
  answer_ptr += 4;

  const char* current_name = bad_horse_names[name_index];
  uint8_t name_len = strlen(current_name);

  *(uint16_t*)answer_ptr = htons(name_len + 2);
  answer_ptr += 2;

  encode_dns_name(answer_ptr, current_name);

  size_t new_dns_size = (answer_ptr + name_len + 2) - dns_data;
  UDP_LEN(udp) = htons(sizeof(struct udphdr) + new_dns_size);

  ip->tot_len = htons(sizeof(struct iphdr) + ntohs(UDP_LEN(udp)));

  ip->check = 0;
  ip->check = compute_checksum((uint16_t*)ip, sizeof(struct iphdr));
  UDP_CHECK(udp) = 0;

  name_index = (name_index + 1) % 27;

  return response;
}

Packet traceroute_answer(Packet input) {
  static int current_hop = 1;

  printf(">>> Generating ICMP Time Exceeded for hop %d\n", current_hop);

  size_t response_size = sizeof(struct ethhdr) + sizeof(struct iphdr) +
                         sizeof(struct icmphdr) + sizeof(struct iphdr) + 8;

  Packet response;
  response.buffer = malloc(response_size);
  response.size = response_size;
  memset(response.buffer, 0, response_size);

  struct ethhdr* eth_req = (struct ethhdr*)input.buffer;
  struct ethhdr* eth_resp = (struct ethhdr*)response.buffer;

  printf(">>> ETH src: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_req->h_source[0],
         eth_req->h_source[1], eth_req->h_source[2], eth_req->h_source[3],
         eth_req->h_source[4], eth_req->h_source[5]);
  printf(">>> ETH dest: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_req->h_dest[0],
         eth_req->h_dest[1], eth_req->h_dest[2], eth_req->h_dest[3],
         eth_req->h_dest[4], eth_req->h_dest[5]);

  memcpy(eth_resp->h_dest, eth_req->h_source, ETH_ALEN);
  memcpy(eth_resp->h_source, eth_req->h_dest, ETH_ALEN);
  eth_resp->h_proto = htons(ETH_P_IP);

  struct iphdr* ip_req = (struct iphdr*)(input.buffer + sizeof(struct ethhdr));
  struct iphdr* ip_resp =
      (struct iphdr*)(response.buffer + sizeof(struct ethhdr));

  ip_resp->version = 4;
  ip_resp->ihl = 5;
  ip_resp->tos = 0;
  ip_resp->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) +
                           sizeof(struct iphdr) + 8);
  ip_resp->id = htons(12345);
  ip_resp->frag_off = 0;
  ip_resp->ttl = 64;
  ip_resp->protocol = IPPROTO_ICMP;

  struct in_addr new_ip;
  inet_pton(AF_INET, "162.252.205.131", &new_ip);
  uint32_t ip_int = ntohl(new_ip.s_addr);
  ip_int = (ip_int & 0xFFFFFF00) | ((131 + current_hop - 1) & 0xFF);
  new_ip.s_addr = htonl(ip_int);

  ip_resp->saddr = new_ip.s_addr;
  ip_resp->daddr = ip_req->saddr;

  ip_resp->check = 0;
  ip_resp->check = compute_checksum((uint16_t*)ip_resp, sizeof(struct iphdr));

  struct icmphdr* icmp =
      (struct icmphdr*)(response.buffer + sizeof(struct ethhdr) +
                        sizeof(struct iphdr));
  icmp->type = ICMP_TIME_EXCEEDED;
  icmp->code = 0;
  icmp->checksum = 0;

  memcpy((char*)(icmp + 1), ip_req, sizeof(struct iphdr) + 8);

  icmp->checksum = compute_checksum(
      (uint16_t*)icmp, sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);

  printf(">>> Sent ICMP Time Exceeded from 162.252.205.%d\n",
         131 + current_hop - 1);

  current_hop++;
  if (current_hop > 27) current_hop = 1;

  return response;
}

filter_status_e traceroute_filter(Packet input) {
  if (input.size < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
    return ACCEPT;
  }

  struct ethhdr* eth = (struct ethhdr*)input.buffer;
  struct iphdr* ip_header =
      (struct iphdr*)(input.buffer + sizeof(struct ethhdr));

  if (ntohs(eth->h_proto) != ETH_P_IP) {
    return ACCEPT;
  }

  struct in_addr target_ip;
  inet_pton(AF_INET, "162.252.205.131", &target_ip);

  if (ip_header->protocol == IPPROTO_UDP &&
      ip_header->daddr == target_ip.s_addr) {
    if (input.size <
        sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr)) {
      return ACCEPT;
    }

    struct udphdr* udp = (struct udphdr*)(input.buffer + sizeof(struct ethhdr) +
                                          sizeof(struct iphdr));

    if (ntohs(UDP_DEST(udp)) >= 33434) {
      printf("UDP traceroute packet to target IP intercepted - dest port: %d\n",
             ntohs(UDP_DEST(udp)));
      return ANSWER;
    }
  }

  return ACCEPT;
}

int main() {
  raw_forwarder_config_t config = {.source_interface = "enp4s0",
                                   .dest_interface = "enp4s0",
                                   .filter = traceroute_filter,
                                   .modify = NULL,
                                   .answer = traceroute_answer,
                                   .data = NULL};

  forwarder_handle_t* handle = create_raw_filter(config);
  if (!handle) {
    fprintf(stderr, "Failed to create raw filter\n");
    return 1;
  }

  printf("Starting ICMP/DNS interceptor...\n");
  if (start_raw_filter(handle) != 0) {
    fprintf(stderr, "Failed to start filter\n");
    destroy_raw_filter(handle);
    return 1;
  }

  printf("Filter running. Press Enter to stop...\n");
  getchar();

  stop_raw_filter(handle);
  destroy_raw_filter(handle);

  return 0;
}