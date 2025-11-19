#include <arpa/inet.h>
#include <linux/version.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <string.h>

#include "include/raw_socket_forwarder.h"

#define TRIGGER_IP "66.66.66.66"
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

const char* trauma_lyrics[] = {"Years.kept.passing.by",
                               "Still.my.mind.hasn-t.forgotten",
                               "Corpses.lying.among.debris",
                               "Unrecognizable.rotten",
                               "Suffering.from.a.trauma",
                               "It.keeps.haunting.me",
                               "Considering.me.an.obsessional",
                               "But.they.will.never.know",
                               "The.massacres.in.former.days",
                               "Hatred.won-t.let.go",
                               "Nightmares.controlling.my.life",
                               "In.my.own.world.I.live",
                               "Suffer.day.and.night",
                               "I.face.pain.I.don-t.want.to.see",
                               "Makes.me.realize",
                               "It.won-t.leave.me",
                               "Horrible.events.pass.me.by",
                               "I.wake.from.my.cry",
                               "In.the.middle.of.the.night",
                               "I.find.myself.shuddering.in.sweat",
                               "Memories.of.sorrow.and.death",
                               "Nightmares.controlling.my.life",
                               "Trauma",
                               "Horrible.events.pass.me.by",
                               "Trauma",
                               "Bodies.filled.with.lead",
                               "They.all.have.met.an.untimely.death",
                               "Blood.was.everywhere",
                               "They.lived.in.chaos.and.despair",
                               "I.suffer.day.and.night",
                               "Trauma",
                               "I.wake.from.my.cries",
                               "Trauma",
                               "Considering.me.an.obsessional",
                               "But.they.will.never.know",
                               "The.massacres.in.former.days",
                               "Hatred.won-t.let.go"};

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

  const char* current_name = trauma_lyrics[name_index];
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
  struct iphdr* ip_in = (struct iphdr*)(input.buffer + sizeof(struct ethhdr));
  struct udphdr* udp_in = (struct udphdr*)(input.buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));

  // Проверяем, это DNS запрос (порт 53) или Traceroute (порт > 33434)
  if (ip_in->protocol == IPPROTO_UDP && ntohs(UDP_DEST(udp_in)) == 53) {
      printf(">>> Generating DNS Response (Lyrics)\n");
      return create_simple_dns_response(input);
  }

  // Если не DNS, значит это Traceroute Probe -> шлем ICMP Time Exceeded
  static int current_hop = 1;
  
  char ip_str[32];
  snprintf(ip_str, sizeof(ip_str), "%s%d", FAKE_NET_PREFIX, current_hop);
  struct in_addr fake_ip;
  inet_pton(AF_INET, ip_str, &fake_ip);

  printf(">>> Generating ICMP from %s\n", ip_str);

  size_t response_size = sizeof(struct ethhdr) + sizeof(struct iphdr) +
                         sizeof(struct icmphdr) + sizeof(struct iphdr) + 8;

  Packet response;
  response.buffer = malloc(response_size);
  response.size = response_size;
  memset(response.buffer, 0, response_size);

  struct ethhdr* eth_req = (struct ethhdr*)input.buffer;
  struct ethhdr* eth_resp = (struct ethhdr*)response.buffer;

  memcpy(eth_resp->h_dest, eth_req->h_source, ETH_ALEN);
  memcpy(eth_resp->h_source, eth_req->h_dest, ETH_ALEN);
  eth_resp->h_proto = htons(ETH_P_IP);

  struct iphdr* ip_resp = (struct iphdr*)(response.buffer + sizeof(struct ethhdr));
  ip_resp->version = 4;
  ip_resp->ihl = 5;
  ip_resp->tos = 0;
  ip_resp->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);
  ip_resp->id = htons(666);
  ip_resp->frag_off = 0;
  ip_resp->ttl = 64;
  ip_resp->protocol = IPPROTO_ICMP;
  ip_resp->saddr = fake_ip.s_addr; // 11.22.33.X
  ip_resp->daddr = ip_in->saddr;   // Original Sender

  ip_resp->check = 0;
  ip_resp->check = compute_checksum((uint16_t*)ip_resp, sizeof(struct iphdr));

  struct icmphdr* icmp = (struct icmphdr*)(response.buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
  icmp->type = ICMP_TIME_EXCEEDED;
  icmp->code = 0;
  icmp->checksum = 0;

  memcpy((char*)(icmp + 1), ip_in, sizeof(struct iphdr) + 8);
  icmp->checksum = compute_checksum((uint16_t*)icmp, sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);

  current_hop++;
  if (current_hop > 35) current_hop = 1; // Сброс после длины песни

  return response;
}

filter_status_e traceroute_filter(Packet input) {
  if (input.size < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
    return ACCEPT;
  }

  struct ethhdr* eth = (struct ethhdr*)input.buffer;
  
  if (ntohs(eth->h_proto) != ETH_P_IP) {
    return ACCEPT;
  }
  
  struct iphdr* ip_header = (struct iphdr*)(input.buffer + sizeof(struct ethhdr));

  if (ip_header->protocol == IPPROTO_UDP) {
      struct udphdr* udp = (struct udphdr*)(input.buffer + sizeof(struct ethhdr) +
                                            sizeof(struct iphdr));
      
      // 1. Перехват Traceroute пакетов (порт назначения > 33434)
      struct in_addr target_ip;
      inet_pton(AF_INET, TRIGGER_IP, &target_ip);

      if (ip_header->daddr == target_ip.s_addr && ntohs(UDP_DEST(udp)) >= 33434) {
          printf(">>> Intercepted Traceroute Probe to %s\n", TRIGGER_IP);
          return ANSWER; // Calls traceroute_answer
      }

      // 2. Перехват DNS запросов (порт назначения 53)
      // Traceroute увидит IP 11.22.33.x и спросит у DNS "кто это?"
      if (ntohs(UDP_DEST(udp)) == 53) {
          // В идеале нужно проверить, что запрос идет именно про нашу подсеть 11.22.33,
          // но для демо можно отвечать на все локальные DNS запросы лирикой.
          printf(">>> Intercepted DNS Query (Likely PTR for lyrics)\n");
          
          // Важно: Функция create_simple_dns_response должна быть объявлена выше
          // Или добавь прототип. Но здесь мы используем хак:
          // Мы возвращаем ANSWER, но нам нужно вызвать другую функцию генерации пакета.
          // Так как структура raw_forwarder_config_t принимает только одну функцию answer,
          // нам придется схитрить внутри main или объединить логику.
          
          // ЛУЧШЕЕ РЕШЕНИЕ ДЛЯ ТЕКУЩЕЙ АРХИТЕКТУРЫ:
          // Вернуть специальный статус или модифицировать traceroute_answer,
          // чтобы она умела отвечать И на ICMP, И на DNS.
          // Давай изменим логику traceroute_answer ниже.
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