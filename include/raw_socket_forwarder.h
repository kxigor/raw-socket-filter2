#ifndef RAW_SOCKET_FORWARDER_H
#define RAW_SOCKET_FORWARDER_H

#include <net/if.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#define BASIC_TIMEOUT_MS 500

typedef enum { ACCEPT, DROP, MODIFY, ANSWER } filter_status_e;

typedef struct {
  char* buffer;
  size_t size;
} Packet;

typedef struct {
  char source_interface[IF_NAMESIZE];
  char dest_interface[IF_NAMESIZE];
  filter_status_e (*filter)(Packet input);
  Packet (*modify)(Packet input);
  Packet (*answer)(Packet input);
  void* data;
} raw_forwarder_config_t;

typedef struct {
  pthread_t filter_thread;
  pthread_t pass_thread;
  
  atomic_bool running_flag;
  raw_forwarder_config_t config;

  int source_socket_fd;
  int dest_socket_fd;

  int error_status;
} forwarder_handle_t;

forwarder_handle_t* create_raw_filter(raw_forwarder_config_t config);

int destroy_raw_filter(forwarder_handle_t* handle);

int start_raw_filter(forwarder_handle_t*);
int stop_raw_filter(forwarder_handle_t*);

int get_forwarder_status(const forwarder_handle_t* handle);
int restart_raw_forwarder(forwarder_handle_t* handle);

#endif  // RAW_SOCKET_FORWARDER_H