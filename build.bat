@echo off

call prebuild.bat

cd build
cmake --build . --config Release --target install
cd ..
