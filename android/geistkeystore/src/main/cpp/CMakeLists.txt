cmake_minimum_required(VERSION 3.22.1)
project(geistkeystore C)

# The JNI shim, and nothing else. It exposes the five C symbols that
# `geist/keystore.nim` imports; see docs/keystore.md for the contract.
add_library(geistkeystore SHARED geist_keystore_jni.c)

find_library(log-lib log)
target_link_libraries(geistkeystore ${log-lib})
