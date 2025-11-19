add_library(raw_socket_forwarder STATIC
    raw_socket_forwarder.c
)

target_include_directories(raw_socket_forwarder
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(raw_socket_forwarder
    PUBLIC
        macros_helpers
        pthread
)

target_link_libraries(raw_socket_forwarder
    PRIVATE
        ${CMAKE_DL_LIBS}
)