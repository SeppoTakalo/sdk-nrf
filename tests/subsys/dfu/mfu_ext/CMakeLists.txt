#
# Copyright (c) 2019 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
#

cmake_minimum_required(VERSION 3.13.1)

set_property(GLOBAL PROPERTY dummy_update_PM_HEX_FILE ${CMAKE_CURRENT_BINARY_DIR}/full_update.hex)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(test_mfu_ext)

target_sources(app
  PRIVATE
  src/main.c
  )

set(GENERATE True)

if (GENERATE)
  generate_cddl(
    ${CMAKE_CURRENT_LIST_DIR}/../../../../subsys/dfu/mfu_ext/modem_update.cddl
    ENTRY_TYPES Wrapper Sig_structure1 Segments
    DECODE
    C_FILE ${CMAKE_CURRENT_LIST_DIR}/../../../../subsys/dfu/mfu_ext/src/modem_update_decode.c
    H_FILE ${CMAKE_CURRENT_LIST_DIR}/../../../../subsys/dfu/mfu_ext/include/modem_update_decode.h
    TYPE_FILE ${CMAKE_CURRENT_LIST_DIR}/../../../../subsys/dfu/mfu_ext/include/modem_update_types.h
    )

  generate_cddl(
    ${CMAKE_CURRENT_LIST_DIR}/../../../../subsys/dfu/mfu_ext/modem_update.cddl
    ENTRY_TYPES Wrapper Sig_structure1 Segments
    ENCODE
    C_FILE ${CMAKE_CURRENT_LIST_DIR}/../../../../subsys/dfu/mfu_ext/src/modem_update_encode.c
    H_FILE ${CMAKE_CURRENT_LIST_DIR}/../../../../subsys/dfu/mfu_ext/include/modem_update_encode.h
    TYPE_FILE ${CMAKE_CURRENT_LIST_DIR}/../../../../subsys/dfu/mfu_ext/include/modem_update_types.h
    )
endif()

# Set srec_cat binary name
find_program(SREC_CAT srec_cat)
if(${SREC_CAT} STREQUAL SREC_CAT-NOTFOUND)
    message(FATAL_ERROR "'srec_cat' not found. Please install it, or add it to $PATH.")
endif()

add_custom_command(
  OUTPUT
  ${CMAKE_CURRENT_BINARY_DIR}/to_be_signed.bin
  ${CMAKE_CURRENT_BINARY_DIR}/blob.bin
  ${CMAKE_CURRENT_BINARY_DIR}/manifest.bin
  ${CMAKE_CURRENT_BINARY_DIR}/signature.bin
  ${CMAKE_CURRENT_BINARY_DIR}/wrapper.bin
  ${CMAKE_CURRENT_BINARY_DIR}/full_update.bin
  ${CMAKE_CURRENT_BINARY_DIR}/full_update.hex
  COMMAND
  ${PYTHON_EXECUTABLE}
  ${ZEPHYR_BASE}/../nrf/scripts/bootloader/modem_update.py
  -o ${CMAKE_CURRENT_BINARY_DIR}
  #-v
  manifest
  -i ${CMAKE_CURRENT_LIST_DIR}/merged.hex
  COMMAND
  ${PYTHON_EXECUTABLE}
  ${ZEPHYR_BASE}/../nrf/scripts/bootloader/do_sign.py
  -i ${CMAKE_CURRENT_BINARY_DIR}/to_be_signed.bin
  -k ${CMAKE_CURRENT_LIST_DIR}/GENERATED_NON_SECURE_PRIVATE_0.pem
  -o ${CMAKE_CURRENT_BINARY_DIR}/signature.bin
  COMMAND
  ${PYTHON_EXECUTABLE}
  ${ZEPHYR_BASE}/../nrf/scripts/bootloader/modem_update.py
  -o ${CMAKE_CURRENT_BINARY_DIR}
  #-v
  wrapper
  -m ${CMAKE_CURRENT_BINARY_DIR}/manifest.bin
  -s ${CMAKE_CURRENT_BINARY_DIR}/signature.bin
  COMMAND
  cp
  ${CMAKE_CURRENT_BINARY_DIR}/wrapper.bin
  ${CMAKE_CURRENT_BINARY_DIR}/full_update.bin
  COMMAND
  cat
  ${CMAKE_CURRENT_BINARY_DIR}/blob.bin
  >>
  ${CMAKE_CURRENT_BINARY_DIR}/full_update.bin
  COMMAND
  srec_cat
  ${CMAKE_CURRENT_BINARY_DIR}/full_update.bin
  -binary
  -offset 0x30000
  -o ${CMAKE_CURRENT_BINARY_DIR}/full_update.hex
  -intel
)
