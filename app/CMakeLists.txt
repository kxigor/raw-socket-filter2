add_executable(trauma_app
  trauma_app.c
)

target_link_libraries(trauma_app PRIVATE
  raw_socket_forwarder
  trace_deceptor
)