cmake_minimum_required(VERSION 3.16)
project(probe C)
add_executable(probe ../probe.c)
# bare framework names: CMake auto-detects .framework on darwin
# (mirrors 74c6414)
message(STATUS "CMAKE_FRAMEWORK_PATH=${CMAKE_FRAMEWORK_PATH}")
target_link_libraries(probe PRIVATE Security CoreFoundation)
