cmake_minimum_required(VERSION 3.16)
project(Encryption_Algorithms_RGR_Modular LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (MSVC)
    add_compile_options(/W4 /utf-8)
else()
    add_compile_options(-Wall -Wextra -finput-charset=UTF-8 -fexec-charset=UTF-8)
endif()

# MinGW: keep the application and plugins independent of the user's installed
# libstdc++/libgcc DLL versions.
if (WIN32 AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_link_options(-static-libgcc -static-libstdc++)
endif()

add_executable(crypto_rgr
    main.cpp
    src/auth.cpp
    src/file_utils.cpp
    src/plugin_loader.cpp
    src/console.cpp
)

target_include_directories(crypto_rgr PRIVATE include)

if (UNIX AND NOT APPLE)
    target_link_libraries(crypto_rgr PRIVATE dl)
endif()

add_library(rsa_plugin SHARED plugins/rsa.cpp)
add_library(elgamal_plugin SHARED plugins/elgamal.cpp)
add_library(wake_plugin SHARED plugins/wake.cpp)

target_include_directories(rsa_plugin PRIVATE include plugins)
target_include_directories(elgamal_plugin PRIVATE include plugins)
target_include_directories(wake_plugin PRIVATE include plugins)

if (WIN32)
    set_target_properties(rsa_plugin PROPERTIES OUTPUT_NAME "rsa" PREFIX "")
    set_target_properties(elgamal_plugin PROPERTIES OUTPUT_NAME "elgamal" PREFIX "")
    set_target_properties(wake_plugin PROPERTIES OUTPUT_NAME "wake" PREFIX "")
else()
    set_target_properties(rsa_plugin PROPERTIES OUTPUT_NAME "rsa" PREFIX "lib")
    set_target_properties(elgamal_plugin PROPERTIES OUTPUT_NAME "elgamal" PREFIX "lib")
    set_target_properties(wake_plugin PROPERTIES OUTPUT_NAME "wake" PREFIX "lib")
endif()

# Keep the runtime layout identical to the hand-written Makefile/build.bat.
add_custom_command(TARGET crypto_rgr POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/password.hash"
        "$<TARGET_FILE_DIR:crypto_rgr>/password.hash"
    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:crypto_rgr>/plugins"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "$<TARGET_FILE:rsa_plugin>"
        "$<TARGET_FILE_DIR:crypto_rgr>/plugins/$<TARGET_FILE_NAME:rsa_plugin>"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "$<TARGET_FILE:elgamal_plugin>"
        "$<TARGET_FILE_DIR:crypto_rgr>/plugins/$<TARGET_FILE_NAME:elgamal_plugin>"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "$<TARGET_FILE:wake_plugin>"
        "$<TARGET_FILE_DIR:crypto_rgr>/plugins/$<TARGET_FILE_NAME:wake_plugin>"
)
