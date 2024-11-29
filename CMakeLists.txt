cmake_minimum_required(VERSION 3.10)

project(TestProject)

find_package(OpenSSL REQUIRED)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR})

include_directories(
    ${CMAKE_SOURCE_DIR}/src/main
)

add_executable(
    start_server
    src/main/main.cpp
    src/index.cpp
)

target_link_libraries(start_server OpenSSL::SSL OpenSSL::Crypto)
