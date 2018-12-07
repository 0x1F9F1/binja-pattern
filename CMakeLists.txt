cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

project(binja_pattern CXX)

set(CMAKE_VS_INCLUDE_INSTALL_TO_DEFAULT_BUILD 1)

if(WIN32)
    set(BINJA_DIR "C:\\Program Files\\Vector35\\BinaryNinja"
        CACHE PATH "Binary Ninja installation directory")
    set(BINJA_BIN_DIR "${BINJA_DIR}")
    set(BINJA_PLUGINS_DIR "$ENV{APPDATA}/Binary Ninja/plugins"
        CACHE PATH "Binary Ninja user plugins directory")
elseif(APPLE)
    set(BINJA_DIR "/Applications/Binary Ninja.app"
        CACHE PATH "Binary Ninja installation directory")
    set(BINJA_BIN_DIR "${BINJA_DIR}/Contents/MacOS")
    set(BINJA_PLUGINS_DIR "$ENV{HOME}/Library/Application Support/Binary Ninja/plugins"
        CACHE PATH "Binary Ninja user plugins directory")
else()
    set(BINJA_DIR "$ENV{HOME}/binaryninja"
        CACHE PATH "Binary Ninja installation directory")
    set(BINJA_BIN_DIR "${BINJA_DIR}")
    set(BINJA_PLUGINS_DIR "$ENV{HOME}/.binaryninja/plugins"
        CACHE PATH "Binary Ninja user plugins directory")
endif()

find_library(BINJA_CORE_LIBRARY
    NAMES binaryninjacore libbinaryninjacore.so.1
    PATHS ${BINJA_BIN_DIR})

message("Binary Ninja Core at " ${BINJA_CORE_LIBRARY})

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    list(APPEND CMAKE_CXX_FLAGS "-fPIC")
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
    include/ParallelFunctions.h
    include/json.hpp)

target_include_directories(${PROJECT_NAME}
    PRIVATE include
    PRIVATE vendor/binaryninja-api)

target_link_libraries(${PROJECT_NAME}
    ${BINJA_CORE_LIBRARY} binaryninjaapi fmt mem Zydis Zycore)

set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 11
    CXX_STANDARD_REQUIRED ON
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin
)

if (WIN32)
    install(TARGETS ${PROJECT_NAME} RUNTIME
        DESTINATION ${BINJA_PLUGINS_DIR})

    install(FILES $<TARGET_PDB_FILE:${PROJECT_NAME}>
        DESTINATION ${BINJA_PLUGINS_DIR} OPTIONAL)
else()
    install(TARGETS ${PROJECT_NAME} LIBRARY
        DESTINATION ${BINJA_PLUGINS_DIR})
endif()
