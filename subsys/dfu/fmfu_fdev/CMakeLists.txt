#
# Copyright (c) 2020 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
#

zephyr_library()

zephyr_library_sources(src/fmfu_fdev.c)
zephyr_library_sources(src/modem_update_decode.c)
zephyr_include_directories(include)

zephyr_compile_definitions(fmfu_fdev CDDL_CBOR_CANONICAL)
