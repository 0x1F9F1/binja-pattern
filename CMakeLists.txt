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

message("Binary Ninja Core at " ${BINJA_CORE_LIBRARY})

add_subdirectory(vendor EXCLUDE_FROM_ALL)

add_library(${PROJECT_NAME} SHARED
    src/main.cpp
    src/PatternScanner.cpp
    include/PatternScanner.h
    include/BackgroundTaskThread.h
    include/BinaryNinja.h)

find_library(BINJA_CORE_LIBRARY binaryninjacore
    HINTS ${BINJA_BIN_DIR})

target_include_directories(${PROJECT_NAME}
    PRIVATE include
    PRIVATE vendor/binaryninja-api)

target_link_libraries(${PROJECT_NAME}
    ${BINJA_CORE_LIBRARY} binaryninjaapi fmt mem)

set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 11
    CXX_STANDARD_REQUIRED ON
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin
)

install(TARGETS ${PROJECT_NAME} RUNTIME
    DESTINATION ${BINJA_PLUGINS_DIR})

install(FILES $<TARGET_PDB_FILE:${PROJECT_NAME}>
    DESTINATION ${BINJA_PLUGINS_DIR} OPTIONAL)
