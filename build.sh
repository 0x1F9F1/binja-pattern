#!/bin/sh

./cmake.sh

cd build
cmake --build . --config Release --target install
cd ..
