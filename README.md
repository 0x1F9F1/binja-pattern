# Binja Pattern
Author: **Brick**

A Binary Ninja plugin to scan for and create patterns/array-of-bytes (e.g. `E8 ? ? ? ? 83 C4 ? 8D 84 24`)

## Compilation
binja-pattern uses CMake, and includes example build scripts `build.bat` (For Visual Studio 2017) and `build.sh`.
If you receive linking errors during compilation, you will need to switch to the appropriate git commit in `vendor/binaryninja-api`, corresponding to your build of Binary Ninja.

## Requirements
Required submodules should be installed by:

    git submodule update --init --recursive
