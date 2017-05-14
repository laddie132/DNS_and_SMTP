cmake_minimum_required(VERSION 3.7)
project(dns_server)

set(CMAKE_C_STANDARD 11)

set(SOURCE_FILES dns.c)
add_executable(dns_server ${SOURCE_FILES})
target_link_libraries(dns_server ws2_32)