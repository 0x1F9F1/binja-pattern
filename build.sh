#!/bin/sh

./prebuild.sh

cd build
cmake --build . --config Release --target install
cd ..
