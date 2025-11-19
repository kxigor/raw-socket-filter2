cmake_minimum_required(VERSION 3.10)
project(RawSocketForwarder C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Подключаем поддиректории
add_subdirectory(include)
add_subdirectory(src)
add_subdirectory(app)