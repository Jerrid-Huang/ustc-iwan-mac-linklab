#!/bin/bash
# control: -framework AFTER the object file (classic working order)
set +e
cd "$(dirname "$0")"
mkdir -p b
echo "LINK LINE: clang ../probe.c -o b/probe -framework Security -framework CoreFoundation"
clang ../probe.c -o b/probe -framework Security -framework CoreFoundation
echo "link-exit=$?"
./b/probe; echo "run-exit=$?"
otool -L b/probe
nm -u b/probe | grep -iE 'CFData|SecItem|CFDictionary' || echo "no undef CF/Sec symbols"
