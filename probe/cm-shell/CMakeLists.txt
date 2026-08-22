cmake_minimum_required(VERSION 3.16)
project(probe C)
add_executable(probe ../probe.c)
# SHELL: keeps "-framework Security" as ONE argument through CMake's
# list machinery (no -lSecurity mangling, no -Wl re-split)
target_link_options(probe PRIVATE "SHELL:-framework Security" "SHELL:-framework CoreFoundation")
