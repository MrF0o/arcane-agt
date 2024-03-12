cmake_minimum_required(VERSION 3.27)
project(arcaneagt)

set(CMAKE_CXX_STANDARD 20)

add_executable(arcaneagt main.cpp)
target_link_libraries(arcaneagt ws2_32 wsock32)
