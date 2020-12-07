#
# Copyright (c) 2020 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
#

zephyr_library()

zephyr_library_link_libraries(MCUMGR)

zephyr_library_sources(
  src/mgmt_fmfu.c
  src/mgmt_fmfu_stat.c
  )
