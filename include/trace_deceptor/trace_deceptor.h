#ifndef TRACE_DECEPTOR_H
#define TRACE_DECEPTOR_H

#include <arpa/inet.h>
#include <linux/version.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "include/raw_socket_forwarder/raw_socket_forwarder.h"

#define FAKE_NET_PREFIX "11.22.33."

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

typedef struct {
  char** lyric_replacements;
  size_t lyrics_size;

  char** spoofed_ips;
  size_t ips_size;
} lyric_spoofer_config_t;

Packet traceroute_answer(const Packet input, void* data);
filter_status_e traceroute_filter(const Packet input, void* data);
void traceroute_cleanup(Packet user_packet, void* /*unused*/);

#endif  // TRACE_DECEPTOR_H