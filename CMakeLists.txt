cmake_minimum_required(VERSION 3.4 FATAL_ERROR)

set(CMAKE_VS_INCLUDE_INSTALL_TO_DEFAULT_BUILD ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

project(binja_pattern CXX)

if(MSVC)
    add_compile_options(/MP)
endif()

add_subdirectory(vendor EXCLUDE_FROM_ALL)

add_library(${PROJECT_NAME} SHARED
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

target_include_directories(${PROJECT_NAME}
    PRIVATE include)

target_link_libraries(${PROJECT_NAME}
    binaryninjaapi fmt mem yaml-cpp Zydis)

set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 11
    CXX_STANDARD_REQUIRED ON)

binja_install_plugin(${PROJECT_NAME})
