cmake_minimum_required(VERSION 3.16)
project(probe C)
add_executable(probe ../probe.c)
# absolute .tbd stub paths: no framework path search at all (nuclear option)
execute_process(COMMAND xcrun --show-sdk-path
                OUTPUT_VARIABLE SDK OUTPUT_STRIP_TRAILING_WHITESPACE)
message(STATUS "SDK=${SDK}")
target_link_libraries(probe PRIVATE
  "${SDK}/System/Library/Frameworks/Security.framework/Security.tbd"
  "${SDK}/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation.tbd")
