#!/bin/bash
# plain -framework BEFORE the object file (the suspected CMake ordering)
set +e
cd "$(dirname "$0")"
mkdir -p b
echo "LINK LINE: clang -framework Security -framework CoreFoundation ../probe.c -o b/probe"
clang -framework Security -framework CoreFoundation ../probe.c -o b/probe
echo "link-exit=$?"
./b/probe; echo "run-exit=$?"
otool -L b/probe
nm -u b/probe | grep -iE 'CFData|SecItem|CFDictionary' || echo "no undef CF/Sec symbols"
