#!/bin/bash
# -Wl,-framework,X comma form BEFORE the object file (CMake's common
# translation when -framework lands in a flag list) + order hypothesis
set +e
cd "$(dirname "$0")"
mkdir -p b
echo "LINK LINE: clang -Wl,-framework,Security -Wl,-framework,CoreFoundation ../probe.c -o b/probe"
clang -Wl,-framework,Security -Wl,-framework,CoreFoundation ../probe.c -o b/probe
echo "link-exit=$?"
./b/probe; echo "run-exit=$?"
otool -L b/probe
nm -u b/probe | grep -iE 'CFData|SecItem|CFDictionary' || echo "no undef CF/Sec symbols"
