cmake_minimum_required(VERSION 3.16)
project(CloudShare CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

add_executable(cloudshare src/main.cpp)

target_include_directories(cloudshare PRIVATE include)
target_link_libraries(cloudshare PRIVATE Threads::Threads OpenSSL::SSL OpenSSL::Crypto SQLite::SQLite3)
