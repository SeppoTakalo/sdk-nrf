/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <zephyr.h>
#include <drivers/flash.h>
#include <logging/log.h>
#include <dfu/dfu_target.h>
#include <dfu/dfu_target_stream.h>

LOG_MODULE_REGISTER(dfu_target_modem_full, CONFIG_DFU_TARGET_LOG_LEVEL);

#define MODEM_FULL_HEADER_MAGIC 0x84d2

static bool configured;

bool dfu_target_modem_full_identify(const void *const buf)
{
	return *((const uint16_t *)buf) == MODEM_FULL_HEADER_MAGIC;
}

int dfu_target_modem_full_cfg(uint8_t *buf, size_t len, struct device *dev,
			      off_t dev_offset, size_t dev_size)
{
	int err;

	err = dfu_target_stream_init("DFU_MODEM_FULL", dev, buf, len,
				     dev_offset, dev_size, NULL);
	if (err != 0) {
		return err;
	}

	configured = true;

	return 0;
}

int dfu_target_modem_full_init(size_t file_size)
{
	if (!configured) {
		return -EPERM;
	}

	return 0;
}

int dfu_target_modem_full_offset_get(size_t *out)
{
	return dfu_target_stream_offset_get(out);
}

int dfu_target_modem_full_write(const void *const buf, size_t len)
{
	return dfu_target_stream_write(buf, len);
}

int dfu_target_modem_full_done(bool successful)
{
	configured = false;

	LOG_INF("FUll modem update completed");

	return dfu_target_stream_done(successful);
}
