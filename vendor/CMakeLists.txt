if(NOT EXISTS "${CMAKE_CURRENT_LIST_DIR}/binaryninja-api")
    find_package(Git)

    if(NOT GIT_FOUND)
        message(FATAL_ERROR "Git not found")
    endif()

    execute_process(
        COMMAND ${GIT_EXECUTABLE} clone "https://github.com/Vector35/binaryninja-api.git"
        WORKING_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}")
endif()

add_subdirectory(binaryninja-api)

add_subdirectory(fmt)
add_subdirectory(mem)

set(YAML_CPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_CONTRIB OFF CACHE BOOL "" FORCE)
set(YAML_CPP_INSTALL OFF CACHE BOOL "" FORCE)
add_subdirectory(yaml-cpp)

set(ZYDIS_MINIMAL_MODE ON CACHE BOOL "" FORCE)
set(ZYDIS_FEATURE_DECODER ON CACHE BOOL "" FORCE)
set(ZYDIS_FEATURE_FORMATTER OFF CACHE BOOL "" FORCE)
set(ZYDIS_FEATURE_AVX512 ON CACHE BOOL "" FORCE)
set(ZYDIS_FEATURE_KNC OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_FUZZ_AFL_FAST OFF CACHE BOOL "" FORCE)
add_subdirectory(zydis)
