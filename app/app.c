#include <arpa/inet.h>
#include <linux/version.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <string.h>

#include "include/raw_socket_forwarder/raw_socket_forwarder.h"
#include "include/trace_deceptor/trace_deceptor.h"

int main() {
  raw_forwarder_config_t config = {.source_interface = "eth0",
                                   .dest_interface = "eth1",
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