add_library(trace_deceptor STATIC trace_deceptor.c)

target_include_directories(trace_deceptor PUBLIC ${CMAKE_SOURCE_DIR})

target_link_libraries(trace_deceptor PUBLIC 
  raw_socket_forwarder
  macros_helpers 
  pthread
)