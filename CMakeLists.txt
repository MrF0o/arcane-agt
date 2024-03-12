cmake_minimum_required(VERSION 3.27)
project(arcaneagt)

set(CMAKE_CXX_STANDARD 20)

add_executable(arcaneagt main.cpp
        net/HttpProxy.cpp
        net/HttpProxy.h
        net/HttpServer.cpp
        net/HttpServer.h
        net/HttpClient.cpp
        net/HttpClient.h
        api/ApiWrapper.cpp
        api/ApiWrapper.h
        scanner/Scanner.cpp
        scanner/Scanner.h
        scanner/RequestScanner.cpp
        scanner/RequestScanner.h)
target_link_libraries(arcaneagt ws2_32 wsock32)
