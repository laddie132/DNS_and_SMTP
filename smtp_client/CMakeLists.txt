cmake_minimum_required(VERSION 3.7)
project(smtp_client)

set(CMAKE_C_STANDARD 11)

set(SOURCE_FILES smtp_client.c base64.c base64.h)
add_executable(smtp_client ${SOURCE_FILES})
target_link_libraries(smtp_client ws2_32)