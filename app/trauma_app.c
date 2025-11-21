#include "trauma_app.h"

#include <arpa/inet.h>
#include <linux/version.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "include/macros_helpers/macros_helpers.h"
#include "include/raw_socket_forwarder/raw_socket_forwarder.h"
#include "include/trace_deceptor/trace_deceptor.h"

#define COPY_IFNAME(dest, src)           \
  do {                                   \
    strncpy(dest, src, IF_NAMESIZE - 1); \
    dest[IF_NAMESIZE - 1] = '\0';        \
  } while (0)

int main(int argc, char** argv) {
  char* source_if = "eth0";
  char* dest_if = "eth1";

  int opt;
  while ((opt = getopt(argc, argv, "s:d:h")) != -1) {
    switch (opt) {
      case 's':
        source_if = optarg;
        break;
      case 'd':
        dest_if = optarg;
        break;
      case 'h':
        printf("Usage: %s [-s source_interface] [-d dest_interface]\n",
               argv[0]);
        printf("Default: source=eth0, dest=eth1\n");
        return 0;
      default:
        fprintf(stderr, "Usage: %s [-s source_interface] [-d dest_interface]\n",
                argv[0]);
        return 1;
    }
  }

  lyric_spoofer_config_t spoofer_config = {.lyric_replacements = trauma_lyrics,
                                           .lyrics_size = trauma_lyrics_size,
                                           .spoofed_ips = spoofed_ips,
                                           .ips_size = spoofed_ips_size};

  raw_forwarder_config_t forwarder_config = {.filter = traceroute_filter,
                                             .modify = NULL,
                                             .answer = traceroute_answer,
                                             .cleanup = traceroute_cleanup,
                                             .data = (void*)&spoofer_config};
  COPY_IFNAME(forwarder_config.source_interface, source_if);
  COPY_IFNAME(forwarder_config.dest_interface, dest_if);

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