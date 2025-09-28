cmake_minimum_required(VERSION 3.22.1)
project("emvport")

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)

# Add include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/proxmark_port)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Define source files for the EMV library
set(EMV_CORE_SOURCES
    proxmark_port/tlv.c
    proxmark_port/dol.c
    proxmark_port/emvcore.c
    proxmark_port/crypto.c
    proxmark_port/crypto_polarssl.c
    proxmark_port/emv_pk.c
    proxmark_port/emv_pki.c
    proxmark_port/emv_pki_priv.c
    proxmark_port/emv_roca.c
    proxmark_port/emv_tags.c
    proxmark_port/emvjson.c
)

# Define test sources (optional for debug builds)
set(EMV_TEST_SOURCES
    proxmark_port/test/crypto_test.c
    proxmark_port/test/cda_test.c
    proxmark_port/test/dda_test.c
    proxmark_port/test/sda_test.c
    proxmark_port/test/cryptotest.c
)

# JNI Bridge sources
set(JNI_SOURCES
    emv_jni.cpp
    nfc_adapter.cpp
    android_crypto.cpp
)

# Create the main EMV library
add_library(emvport SHARED
    ${EMV_CORE_SOURCES}
    ${JNI_SOURCES}
)

# Find required libraries
find_library(log-lib log)
find_library(android-lib android)

# Link libraries
target_link_libraries(emvport
    ${log-lib}
    ${android-lib}
)

# Compiler definitions
target_compile_definitions(emvport PRIVATE
    ANDROID_BUILD=1
    EMV_ANDROID_PORT=1
)

# Add debug symbols for debug builds
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(emvport PRIVATE -g -O0)
    target_compile_definitions(emvport PRIVATE DEBUG=1)
    
    # Include test sources in debug builds
    target_sources(emvport PRIVATE ${EMV_TEST_SOURCES})
endif()

# Optimization for release builds
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(emvport PRIVATE -O3)
    target_compile_definitions(emvport PRIVATE NDEBUG=1)
endif()