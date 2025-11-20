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
#include "include/macros_helpers/macros_helpers.h"

int main() {
  raw_forwarder_config_t config = {.source_interface = "eth0",
                                   .dest_interface = "eth1",
                                   .filter = traceroute_filter,
                                   .modify = NULL,
                                   .answer = traceroute_answer,
                                   .data = NULL};

  forwarder_handle_t* handle;
  CHECK_SYSCALL_RES(
    /*res*/ handle,
    /*sys*/ create_raw_filter(config),
    /*exp*/ NULL,
    /*ret*/ return SYSERRCODE
  );

  LOG_INFO_LUXERY("Starting ICMP/DNS interceptor");

  CHECK_SYSCALL_NOE(
    /*res*/ start_raw_filter(handle),
    /*noe*/ 0,
    /*ret*/ return SYSERRCODE
  );

  LOG_INFO("Filter running. Press Enter to stop...\n");
  getchar();

  stop_raw_filter(handle);
  destroy_raw_filter(handle);

  return 0;
}