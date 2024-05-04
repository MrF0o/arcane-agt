cmake_minimum_required(VERSION 3.27)
project(arcaneagt)

set(CMAKE_CXX_STANDARD 20)
add_compile_definitions(BOOST_ASIO_DISABLE_IOCP)

add_executable(arcaneagt main.cpp
        net/HttpProxy.cpp
        net/HttpServer.cpp
        net/HttpClient.cpp
        api/ApiWrapper.cpp
        scanner/Scanner.cpp
        scanner/RequestScanner.cpp
        scanner/ScanResult.cpp
        scanner/ScannerConfig.cpp
        scanner/rules/rules.cpp
        scanner/rules/request/ProtocolEnforcement.h
        scanner/rules/response/WebShells.h)
target_include_directories(arcaneagt PRIVATE ${PROJECT_SOURCE_DIR})
target_link_libraries(arcaneagt ws2_32 wsock32 pthread)
