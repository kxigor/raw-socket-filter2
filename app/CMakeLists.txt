add_executable(raw_socket_app
    app.c
)

target_include_directories(raw_socket_app
    PRIVATE
        ${CMAKE_SOURCE_DIR}
)

target_link_libraries(raw_socket_app
    PRIVATE
        raw_socket_forwarder
)