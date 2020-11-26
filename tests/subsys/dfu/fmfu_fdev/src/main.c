/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <string.h>
#include <zephyr/types.h>
#include <stdbool.h>
#include <ztest.h>
#include <device.h>
#include <drivers/flash.h>
#include <dfu/fmfu_fdev.h>

#if USE_PARTITION_MANAGER
#include <pm_config.h>
#endif

/* TODO replace this with actual data, make it bigger than the buf */
static const uint8_t data[] = {0x10, 0xab, 0x10};

#define BUF_SIZE (8*1024)
static uint8_t buf[BUF_SIZE];

/* TODO provide overlay for 9160 DK to use ext flash */
#define FLASH_NAME DT_CHOSEN_ZEPHYR_FLASH_CONTROLLER_LABEL

#define OFFSET 0x20000 /* Same used when generating the segments */

int mfu_stream_chunk(const struct memory_chunk *chunk)
{
	return 0;

}


int mfu_stream_end(void)
{
	return 0;
}


uint8_t mfu_pk[] = {
	0x04,
	0x2b, 0xc7, 0xa8, 0xa9, 0xc6, 0x4d, 0x67, 0xcd,
	0x02, 0xe7, 0xdb, 0x6a, 0xf6, 0x9b, 0x11, 0x23,
	0x3d, 0xb5, 0x97, 0x88, 0x61, 0x4e, 0xe1, 0x06,
	0x4a, 0x28, 0x9a, 0x20, 0xcb, 0x92, 0xd9, 0x8a,
	0x86, 0xdb, 0x08, 0x98, 0x1f, 0xb4, 0x44, 0xc8,
	0x81, 0x8c, 0x31, 0xbf, 0x4b, 0x33, 0x61, 0x4e,
	0xcd, 0x43, 0xe9, 0xff, 0x12, 0x13, 0xdb, 0x92,
	0xdb, 0x04, 0x6c, 0x8a, 0x71, 0x87, 0x08, 0xda
};

static void test_fmfu_fdev_load_segments(void)
{
	/* Generate a hex file with five segments, 0x20000 and on.
	 * Serialize this and copy the C array of these segments and its
	 * header to flash. Next, perform the fmfu_fdev_load operation
	 * and verify that the contents passed is correct.
	 */
	int err;
	const struct device *fdev = device_get_binding(FLASH_NAME);

	err = flash_write(fdev, OFFSET, data, sizeof(data));
	zassert_true(err == 0, "Unexpected failure: %d", err);

	err = fmfu_fdev_init(buf, sizeof(buf));
	zassert_true(err == 0, "Unexpected failure");

	// err = fmfu_fdev_load(fdev, OFFSET);
	// zassert_true(err == 0, "Unexpected failure");
}


static void test_fmfu_fdev_prevalidate(void)
{
	const struct device *fdev = device_get_binding(FLASH_NAME);
	bool valid = false;
	uint32_t seg_offset, blob_offset;
	int err;

	err = fmfu_fdev_init(buf, sizeof(buf));
	zassert_true(err == 0, "Unexpected failure");

	err = fmfu_fdev_prevalidate(fdev, PM_DUMMY_UPDATE_ADDRESS, &valid,
					&seg_offset, &blob_offset);

	zassert_equal(0, err, "%d", err);
	zassert_true(valid, NULL);

}

void test_main(void)
{
	ztest_test_suite(lib_fmfu_fdev_test,
	     ztest_unit_test(test_fmfu_fdev_load_segments),
	     ztest_unit_test(test_fmfu_fdev_prevalidate)
	 );

	ztest_run_test_suite(lib_fmfu_fdev_test);
}
