cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

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
    CXX_STANDARD_REQUIRED ON
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin
)

binja_install_plugin(${PROJECT_NAME})
