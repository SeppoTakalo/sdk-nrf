#
# Copyright (c) 2020 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
#

zephyr_library()

zephyr_library_sources(src/mfu_ext.c)
zephyr_library_sources(src/modem_update_encode.c src/modem_update_decode.c)
zephyr_library_include_directories(include)

zephyr_compile_definitions(mfu_ext CDDL_CBOR_CANONICAL)
