cmake_minimum_required(VERSION 3.16)
project(probe C)
add_executable(probe ../probe.c)
# LINK_FLAGS property (same class as the CMAKE_EXE_LINKER_FLAGS
# attempt 58262de; flags are placed right after the rule's flags)
set_target_properties(probe PROPERTIES LINK_FLAGS "-framework Security -framework CoreFoundation")
