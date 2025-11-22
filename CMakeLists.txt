cmake_minimum_required(VERSION 3.28.3)
project(krakensdr_sigmf)

add_executable(krakensdr_sigmf
        src/log.cpp
        src/krakenrf_sigmf.cpp
      )
      
target_include_directories(krakensdr_sigmf 
    PRIVATE # Used only for MyExecutable's own compilation
        ${CMAKE_CURRENT_SOURCE_DIR}/include 
        )

find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)
target_link_libraries(krakensdr_sigmf OpenSSL::SSL OpenSSL::Crypto)
