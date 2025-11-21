#include "include/raw_socket_forwarder/raw_socket_forwarder.h"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "include/macros_helpers/macros_helpers.h"

// clang-format off
forwarder_handle_t* create_raw_filter(raw_forwarder_config_t config) {
  LOG_INFO("Creating raw filter handle");

  forwarder_handle_t* handle;
  CHECK_SYSCALL_RES(
    /*res*/ handle,
    /*sys*/ calloc(1, sizeof(forwarder_handle_t)),
    /*exp*/ NULL,
    /*ret*/ return NULL
  );

  handle->filter_thread = 0;
  handle->pass_thread = 0;
  handle->config = config;
  atomic_init(&handle->running_flag, false);
  handle->source_socket_fd = -1;
  handle->dest_socket_fd = -1;

  LOG_INFO("Raw filter handle created successfully");
  LOG_INFO("Source interface: %s, Destination interface: %s", 
           config.source_interface, config.dest_interface);

  return handle;
}

int destroy_raw_filter(forwarder_handle_t* handle) {
  LOG_INFO("Destroying raw filter handle");

  free(handle);
  return 0;
}

static int init_socket(const char* if_name) {
  LOG_INFO("Initializing socket for interface: %s", if_name);

  const uint16_t kProtocol = htons(ETH_P_ALL);
  LOG_DEBUG("Using protocol: 0x%04x", ntohs(kProtocol));

  unsigned int if_index;
  CHECK_SYSCALL_RES(
    /*res*/ if_index, 
    /*sys*/ if_nametoindex(if_name),
    /*exp*/ INVALID_IFINDEX,
    /*ret*/ return SYSERRCODE;
  );
  LOG_INFO("Interface %s has index: %d", if_name, if_index);

  int socket_fd;
  CHECK_SYSCALL_RES(
    /*res*/ socket_fd, 
    /*sys*/ socket(AF_PACKET, SOCK_RAW, kProtocol),
    /*exp*/ INVALID_SOCKET,
    /*ret*/ return SYSERRCODE;
  );
  LOG_INFO("Raw socket created successfully, fd: %d", socket_fd);

  struct sockaddr_ll addr_ll = {
    .sll_family = AF_PACKET,
    .sll_protocol = kProtocol,
    .sll_ifindex = if_index
  };

  CHECK_SYSCALL(
    /*sys*/ bind(
              socket_fd, 
              (const struct sockaddr*)&addr_ll, 
              sizeof(addr_ll)
            ),
    /*exp*/ INVALID_BIND,
    /*ret*/ return SYSERRCODE;
  );

  LOG_INFO("Socket successfully bound to interface %s", if_name);
  return socket_fd;
}

static void stop_processor_thread(forwarder_handle_t* handle) {
  LOG_INFO("Stopping processor threads");
  atomic_store(&handle->running_flag, false);
  LOG_DEBUG("Running flag set to false");
}

static void* filter_processor_thread(void* arg) {
  forwarder_handle_t* handle = (forwarder_handle_t*)arg;
  char buffer[ETH_FRAME_LEN];

  LOG_INFO("Filter processor thread started");
  LOG_DEBUG("Thread will process packets from %s to %s", 
           handle->config.source_interface, handle->config.dest_interface);

  while(atomic_load(&handle->running_flag)) {
    ssize_t bytes_received = recv(
      handle->source_socket_fd, 
      buffer,
      sizeof(buffer),
      0
    );

    if (bytes_received <= 0) {
      if (bytes_received == 0) {
        LOG_DEBUG("Connection closed gracefully, bytes_received = 0");
        continue;
      } else {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          LOG_DEBUG("Receive timeout (EAGAIN/EWOULDBLOCK), continuing");
          continue;
        } else if (errno == EINTR) {
          LOG_DEBUG("Receive interrupted by signal, continuing");
          continue;
        } else {
          LOG_ERROR("Critical recv error: %s (errno=%d)", strerror(errno), errno);
          return NULL;
        }
      }
    }

    Packet packet = {
      .buffer = buffer,
      .size = (size_t)bytes_received
    };

    filter_status_e filter_status = handle->config.filter(packet, handle->config.data);

    switch (filter_status)
    {
    case ACCEPT: {
      WARN_SYSCALL(
        /*sys*/ send(
                  handle->dest_socket_fd,
                  buffer,
                  bytes_received,
                  0
                ),
        /*exp*/ INVALID_SEND
      );
    } break;
    case MODIFY: {
      LOG_INFO("Generating modified packet");
      Packet modified = handle->config.modify(packet, handle->config.data);
      if(modified.size == 0) {
        LOG_WARN("Modify function returned empty packet, skipping send");
        break;
      }
      LOG_INFO("Sending modified packet, size: %zu", modified.size);
      WARN_SYSCALL(
        /*sys*/ send(
                  handle->dest_socket_fd,
                  modified.buffer,
                  modified.size,
                  0
                ),
        /*exp*/ INVALID_SEND
      );
      LOG_INFO("Modified packet sent successfully, %zu bytes delivered", modified.size);
      LOG_DEBUG("Cleaning up packet buffer (%zu bytes)", modified.size);
      handle->config.cleanup(modified, handle->config.data);
      LOG_DEBUG("Packet cleanup completed");
    } break;
    case ANSWER: {
      LOG_INFO("Generating answer for packet");
      Packet answer = handle->config.answer(packet, handle->config.data);
      if(answer.size == 0) {
        LOG_WARN("Answer function returned empty packet, skipping send");
        break;
      }
      LOG_INFO("Sending answer packet, size: %zu", answer.size);
      ssize_t answer_sended_size;
      WARN_SYSCALL_RES(
        /*res*/ answer_sended_size,
        /*sys*/ send(
                  handle->source_socket_fd,
                  answer.buffer,
                  answer.size,
                  0
                ),
        /*exp*/ INVALID_SEND
      );
      LOG_INFO("Answer packet sent successfully, %zd bytes delivered", answer_sended_size);
      LOG_DEBUG("Cleaning up packet buffer (%zu bytes)", answer.size);
      handle->config.cleanup(answer, handle->config.data);
      LOG_DEBUG("Packet cleanup completed");
    } break;
    case DROP: {
      LOG_INFO("Dropping packet (%zd bytes)", bytes_received);
    } break;
    default: {
      LOG_WARN("Unknown filter status %d, dropping packet", filter_status);
    } break;
    }
  }

  LOG_INFO("Filter processor thread stopped");
  return NULL;
}

static void* pass_processor_thread(void* arg) {
  forwarder_handle_t* handle = (forwarder_handle_t*)arg;
  char buffer[ETH_FRAME_LEN] = {};

  LOG_INFO("Pass processor thread started");
  LOG_DEBUG("Thread will forward packets from %s back to %s", 
           handle->config.dest_interface, handle->config.source_interface);

  while(atomic_load(&handle->running_flag) == true) {
    ssize_t bytes_received;
    WARN_SYSCALL_RES(
      /*res*/ bytes_received,
      /*sys*/ recv(
                handle->dest_socket_fd, 
                buffer,
                sizeof(buffer),
                0
              ),
      /*exp*/ INVALID_RECV
    );
    WARN_SYSCALL(
      /*sys*/ send(
                handle->source_socket_fd, 
                buffer,
                bytes_received,
                0
              ),
      /*exp*/ INVALID_SEND
    );
  }

  LOG_INFO("Pass processor thread stopped");
  return NULL;
}

static int setup_socket_timeout(int socket_fd, int timeout_ms) {
  LOG_INFO("Setting socket timeout to %d ms for fd: %d", timeout_ms, socket_fd);
  struct timeval timeout = {
    .tv_sec = timeout_ms / 1000,
    .tv_usec = (timeout_ms % 1000) * 1000
  };

  CHECK_SYSCALL(
    /*sys*/ setsockopt(
              socket_fd, 
              SOL_SOCKET, 
              SO_RCVTIMEO, 
              &timeout, 
              sizeof(timeout)
            ),
    /*exp*/ INVALID_SETSOCK,
    /*ret*/ return SYSERRCODE;
  );

  LOG_INFO("Socket timeout set successfully");
  return 0;
}

int start_raw_filter(forwarder_handle_t* handle) {
  LOG_INFO("Starting raw filter");

  if(atomic_load(&handle->running_flag) == true) {
    LOG_ERROR("Raw filter is already running!");
    return SYSERRCODE;
  }

  atomic_store(&handle->running_flag, true);
  LOG_DEBUG("Running flag set to true");

  CHECK_SYSCALL_RES(
    /*res*/ handle->source_socket_fd,
    /*sys*/ init_socket(handle->config.source_interface),
    /*exp*/ SYSERRCODE,
    /*ret*/ return SYSERRCODE  
  );

  CHECK_SYSCALL(
    /*sys*/ setup_socket_timeout(
              handle->source_socket_fd,
              BASIC_TIMEOUT_MS
            ),
    /*exp*/ SYSERRCODE,
    /*ret*/ return SYSERRCODE
  );
    
  CHECK_SYSCALL_RES(
    /*res*/ handle->dest_socket_fd,
    /*sys*/ init_socket(handle->config.dest_interface),
    /*exp*/ SYSERRCODE,
    /*ret*/ return SYSERRCODE
  );

  CHECK_SYSCALL_NOE(
    /*sys*/ pthread_create(
              &handle->pass_thread, 
              NULL, 
              pass_processor_thread, 
              handle
            ),
    /*noe*/ SUCCESS_PTHREAD,
    /*ret*/ return SYSERRCODE
  );
  LOG_INFO("Pass processor thread created, ID: %lu", (uintptr_t)handle->pass_thread);

  CHECK_SYSCALL_NOE(
    /*sys*/ pthread_create(
              &handle->filter_thread, 
              NULL, 
              filter_processor_thread, 
              handle
            ),
    /*noe*/ SUCCESS_PTHREAD,
    /*ret*/ return SYSERRCODE
  );
  LOG_INFO("Filter processor thread created, ID: %lu", (uintptr_t)handle->filter_thread);

  LOG_INFO("Raw filter started successfully");
  LOG_INFO("Forwarding packets: %s <-> %s", 
           handle->config.source_interface, handle->config.dest_interface);
  return 0;
}

int stop_raw_filter(forwarder_handle_t* handle) {
  LOG_INFO("Stopping raw filter");

  if(atomic_load(&handle->running_flag) == false) {
    LOG_ERROR("Raw filter is already stopped!");
    return SYSERRCODE;
  }

  stop_processor_thread(handle);
  LOG_INFO("Raw filter stopped successfully");
  return 0;
}

// clang-format on