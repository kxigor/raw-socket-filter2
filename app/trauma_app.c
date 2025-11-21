#include "trauma_app.h"

#include <arpa/inet.h>
#include <linux/version.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <string.h>

#include "include/macros_helpers/macros_helpers.h"
#include "include/raw_socket_forwarder/raw_socket_forwarder.h"
#include "include/trace_deceptor/trace_deceptor.h"

int main() {
  lyric_spoofer_config_t spoofer_config = {.lyric_replacements = trauma_lyrics,
                                           .lyrics_size = trauma_lyrics_size,
                                           .spoofed_ips = spoofed_ips,
                                           .ips_size = spoofed_ips_size};

  raw_forwarder_config_t forwarder_config = {.source_interface = "eth0",
                                             .dest_interface = "eth1",
                                             .filter = traceroute_filter,
                                             .modify = NULL,
                                             .answer = traceroute_answer,
                                             .cleanup = traceroute_cleanup,
                                             .data = (void*)&spoofer_config};

  forwarder_handle_t* handle;
  CHECK_SYSCALL_RES(
      /*res*/ handle,
      /*sys*/ create_raw_filter(forwarder_config),
      /*exp*/ NULL,
      /*ret*/ return SYSERRCODE);

  LOG_INFO_LUXERY("Starting ICMP/DNS interceptor");

  CHECK_SYSCALL_NOE(
      /*sys*/ start_raw_filter(handle),
      /*noe*/ 0,
      /*ret*/ return SYSERRCODE);

  LOG_INFO("Filter running. Press Enter to stop...");
  getchar();

  CHECK_SYSCALL_NOE(
      /*sys*/ stop_raw_filter(handle),
      /*noe*/ 0,
      /*ret*/ return SYSERRCODE);

  CHECK_SYSCALL_NOE(
      /*sys*/ destroy_raw_filter(handle),
      /*noe*/ 0,
      /*ret*/ return SYSERRCODE);

  return 0;
}