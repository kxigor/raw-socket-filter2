add_executable(raw_socket_app
  app.c
)

target_link_libraries(raw_socket_app PRIVATE
  raw_socket_forwarder
  trace_deceptor
)