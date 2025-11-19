#include "include/raw_socket_forwarder.h"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "include/macros_helpers.h"

forwarder_handle_t* create_raw_filter(raw_forwarder_config_t config) {
  forwarder_handle_t* handle = calloc(1, sizeof(forwarder_handle_t));

  handle->thread = 0;
  handle->config = config;
  atomic_init(&handle->running_flag, false);
  handle->source_socket_fd = -1;
  handle->dest_socket_fd = -1;

  return handle;
}

int destroy_raw_filter(forwarder_handle_t* handle) {
  free(handle);

  return 0;
}

// clang-format off

static int init_socket(const char* if_name) {
  const uint16_t kProtocol = htons(ETH_P_ALL);

  unsigned int if_index;
  CHECK_SYSCALL_RES_VAL(
    if_index, 
    if_nametoindex(if_name),
    0
  );

  int socket_fd;
  CHECK_SYSCALL_RES(
    socket_fd, 
    socket(AF_PACKET, SOCK_RAW, kProtocol)
  );

  struct sockaddr_ll addr_ll = {
    .sll_family = AF_PACKET,
    .sll_protocol = kProtocol,
    .sll_ifindex = if_index
  };

  CHECK_SYSCALL(
    bind(
      socket_fd, 
      (const struct sockaddr*)&addr_ll, 
      sizeof(addr_ll)
    )
  );

  return socket_fd;
}

static void stop_processor_thread(forwarder_handle_t* handle) {
  atomic_store(&handle->running_flag, false);
}

static void* packet_processor_thread(void* arg) {
  forwarder_handle_t* handle = (forwarder_handle_t*)arg;
  char buffer[ETH_FRAME_LEN];

  while(atomic_load(&handle->running_flag)) {
    ssize_t bytes_received = recv(
      handle->source_socket_fd, 
      buffer,
      sizeof(buffer),
      0
    );

    if(bytes_received == -1) {
      handle->error_status = errno;
      stop_processor_thread(handle);
    }

    if (bytes_received == 0) {
      continue;
    }

    Packet packet = {
      .buffer = buffer,
      .size = (size_t)bytes_received
    };

    filter_status_e filter_status = handle->config.filter(packet);

    switch (filter_status)
    {
    case ACCEPT: {
      printf("bytes_received : %ld\n", bytes_received);
      CHECK_SYSCALL_NR(
        send(
          handle->dest_socket_fd,
          buffer,
          bytes_received,
          0
        )
      );

    } break;
    case MODIFY: {
      Packet modified = handle->config.modify(packet);
      CHECK_SYSCALL_NR(
        send(
          handle->dest_socket_fd,
          modified.buffer,
          modified.size,
          0
        )
      );

    } break;
    case ANSWER: {
    printf(">>> ANSWER - processing with answer function\n");
    Packet answer = handle->config.answer(packet);
    printf(">>> Sending answer packet, size: %zu\n", answer.size);
      CHECK_SYSCALL_NR(
        send(
          handle->source_socket_fd,
          answer.buffer,
          answer.size,
          0
        )
      );
    } break;
    case DROP:
    default:
      break;
    }
  }
  return NULL;
}

static int setup_socket_timeout(int socket_fd, int timeout_ms) {
  struct timeval timeout = {
    .tv_sec = timeout_ms / 1000,
    .tv_usec = (timeout_ms % 1000) * 1000
  };

  return setsockopt(
    socket_fd, 
    SOL_SOCKET, 
    SO_RCVTIMEO, 
    &timeout, 
    sizeof(timeout)
  );
}

int start_raw_filter(forwarder_handle_t* handle) {
  CHECK_SYSCALL_RES(
    handle->source_socket_fd,
    init_socket(handle->config.source_interface)
  );

  CHECK_SYSCALL(
    setup_socket_timeout(
      handle->source_socket_fd,
      BASIC_TIMEOUT_MS
    )
  );
    
  CHECK_SYSCALL_RES(
    handle->dest_socket_fd,
    init_socket(handle->config.dest_interface)
  );

  atomic_store(&handle->running_flag, true);

  CHECK_SYSCALL(
    pthread_create(
      &handle->thread, 
      NULL, 
      packet_processor_thread, 
      handle
    )
  );


  return 0;
}

int stop_raw_filter(forwarder_handle_t* handle) {
  stop_processor_thread(handle);
}

// clang-format on