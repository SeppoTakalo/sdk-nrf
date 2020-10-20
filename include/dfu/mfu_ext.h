/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#ifndef MFU_EXT_H__
#define MFU_EXT_H__

#include <dfu/mfu_stream.h>

int mfu_ext_init(uint8_t *buf_in, size_t buf_len);

int mfu_ext_prevalidate(const struct device *fdev, size_t offset, bool *valid,
			uint32_t *seg_offset, uint32_t *blob_offset);


int mfu_ext_load(const struct device *fdev, size_t seg_offset, size_t blob_offset);

#endif /* MFU_EXT_H__ */
