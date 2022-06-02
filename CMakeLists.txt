cmake_minimum_required(VERSION 3.4 FATAL_ERROR)

set(CMAKE_VS_INCLUDE_INSTALL_TO_DEFAULT_BUILD ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

project(binja-pattern CXX)

if(MSVC)
    add_compile_options(/MP)
endif()

add_subdirectory(vendor EXCLUDE_FROM_ALL)

add_library(binja-pattern SHARED
    src/main.cpp
    src/PatternScanner.cpp
    src/PatternLoader.cpp
    src/PatternMaker.cpp
    src/BinaryNinja.cpp
    include/PatternScanner.h
    include/PatternLoader.h
    include/BackgroundTaskThread.h
    include/BinaryNinja.h
    include/ParallelFunctions.h)

target_include_directories(binja-pattern
    PRIVATE include)

target_link_libraries(binja-pattern
    binaryninjaapi fmt mem yaml-cpp Zydis)

set_target_properties(binja-pattern PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON)

get_target_property(BN_API_SOURCE_DIR binaryninjaapi SOURCE_DIR)
list(APPEND CMAKE_MODULE_PATH "${BN_API_SOURCE_DIR}/cmake")
find_package(BinaryNinjaCore REQUIRED)

bn_install_plugin(binja-pattern)
install(FILES "python/binarypattern.py" DESTINATION ${BN_USER_PLUGINS_DIR})

