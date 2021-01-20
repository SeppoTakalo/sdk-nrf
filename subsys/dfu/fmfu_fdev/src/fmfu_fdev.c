/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <modem_update_decode.h>
#include <drivers/flash.h>
#include <logging/log.h>
#include <dfu/fmfu_fdev.h>
#include <nrf_fmfu.h>
#include <mbedtls/sha256.h>

LOG_MODULE_REGISTER(fmfu_fdev, CONFIG_FMFU_FDEV_LOG_LEVEL);

#define MAX_META_LEN 1000

static uint8_t meta_buf[1024];

static int get_hash_from_flash(const struct device *fdev, size_t offset,
			       size_t data_len, uint8_t *hash, uint8_t *buffer,
			       size_t buffer_len)
{
	int err;
	mbedtls_sha256_context sha256_ctx;
	size_t end = offset + data_len;

	mbedtls_sha256_init(&sha256_ctx);

	err = mbedtls_sha256_starts_ret(&sha256_ctx, false);
	if (err != 0) {
		return err;
	}

	for (size_t p_offs = offset; p_offs < end; p_offs += buffer_len) {
		size_t part_len = MIN(buffer_len, (end - p_offs));
		int err = flash_read(fdev, p_offs, buffer, part_len);

		if (err != 0) {
			return err;
		}

		err = mbedtls_sha256_update_ret(&sha256_ctx, buffer, part_len);
		if (err != 0) {
			return err;
		}
	}

	err = mbedtls_sha256_finish_ret(&sha256_ctx, hash);
	if (err != 0) {
		return err;
	}

	return 0;
}

static int load_segment(const struct device *fdev, size_t seg_size,
			uint32_t seg_target_addr, uint32_t seg_offset,
			uint8_t *buf)
{
	int err;
	uint32_t read_addr = seg_offset;
	size_t bytes_left = seg_size;

	while (bytes_left) {
		uint32_t read_len = MIN(NRF_MODEM_FULL_DFU_SHM_LEN, bytes_left);

		err = flash_read(fdev, read_addr, buf, read_len);
		if (err != 0) {
			LOG_ERR("flash_read failed2: %d", err);
			return err;
		}

		err = nrf_modem_full_dfu_fw_write(seg_target_addr, read_len,
						  buf);
		if (err != 0) {
			LOG_ERR("nrf_modem_full_dfu_fw_write failed: %d", err);
			return err;
		}

		LOG_DBG("wrote chunk: offset 0x%x target addr 0x%x size 0x%x",
			read_addr, seg_target_addr, read_len);

		seg_target_addr += read_len;
		bytes_left -= read_len;
		read_addr += read_len;
	}

	return 0;
}

static int prevalidate(uint8_t *buf, size_t wrapper_len)
{
	int err;

	err = nrf_modem_full_dfu_verify(wrapper_len, (void *)buf);
	if (err != 0) {
		LOG_ERR("nrf_modem_full_dfu_verify failed: %d", errno);
	}

	return err;
}

static int load_segments(const struct device *fdev, uint8_t *meta_buf,
			 size_t wrapper_len, const Segments_t *seg,
			 size_t blob_offset, uint8_t *buf)
{
	int err;
	size_t prev_segments_len = 0;

	LOG_INF("Writing %d segments", seg->_Segments__Segment_count);

	for (int i = 0; i < seg->_Segments__Segment_count; i++) {
		size_t seg_size = seg->_Segments__Segment[i]._Segment_len;
		uint32_t seg_addr =
			seg->_Segments__Segment[i]._Segment_target_addr;
		uint32_t read_addr = blob_offset + prev_segments_len;

		err = nrf_modem_full_dfu_begin();
		if (err != 0) {
			LOG_ERR("nrf_modem_full_dfu_begin failed: %d", err);
			return err;
		}

		err = load_segment(fdev, seg_size, seg_addr, read_addr, buf);
		if (err != 0) {
			LOG_ERR("load_segment failed: %d", err);
			return err;
		}

		LOG_DBG("Modem state: %d", nrf_modem_full_dfu_state());

		err = nrf_modem_full_dfu_apply();
		if (err != 0) {
			LOG_ERR("nrf_modem_full_dfu_apply failed, state: %d errno: %d",
				nrf_modem_full_dfu_state(), errno);
			return err;
		}

		if (i == 0) {
			/* This is the first segment, which contains the
			 * IPC-DFU bootloader. We can now perform the
			 * signature verification.
			 */
			err = prevalidate(meta_buf, wrapper_len);
			if (err != 0) {
				LOG_ERR("Prevalidate failed: %d", err);
				return err;
			}
		}

		prev_segments_len += seg_size;

		LOG_INF("Segment %d written. Target addr: 0x%x, size: 0%x",
			i, seg_addr, seg_size);
	}

	LOG_INF("FMFU finished");

	return 0;
}

int fmfu_fdev_load(uint8_t *buf, size_t buf_len,
		   const struct device *fdev, size_t offset)
{
	const cbor_string_type_t *segments_string;
	COSE_Sign1_Manifest_t wrapper;
	bool hash_len_valid = false;
	uint8_t expected_hash[32];
	bool hash_valid = false;
	Segments_t segments;
	size_t blob_offset;
	size_t wrapper_len;
	uint8_t hash[32];
	size_t blob_len;
	int err;

	if (buf == NULL || fdev == NULL) {
		return -ENOMEM;
	}

	/* Put modem in DFU/RPC state */
	err = nrf_modem_full_dfu_init(NULL, NRF_MODEM_FULL_DFU_SHM_LEN,
		       	(uint8_t *)0x20010000);
	if (err != 0) {
		LOG_ERR("nrf_modem_full_dfu_init failed, errno: %d\n.", errno);
		return err;
	}

	/* Read the whole wrapper. */
	err = flash_read(fdev, offset, meta_buf, MAX_META_LEN);
	if (err != 0) {
		return err;
	}

	if (!cbor_decode_Wrapper(meta_buf, MAX_META_LEN, &wrapper, &wrapper_len)) {
		return -EINVAL;
	}

	/* Add the base offset of the wrapper to the blob offset to get the
	 * absolute offset to the blob in the flash device.
	 */
	blob_offset = wrapper_len + offset;

	/* Get a pointer to, and decode,  the segments as this is a cbor encoded
	 * structure in itself.
	 */
	segments_string = &wrapper._COSE_Sign1_Manifest_payload_cbor
			._Manifest_segments;
	if (!cbor_decode_Segments(segments_string->value,
				  segments_string->len, &segments, NULL)) {
		return -EINVAL;
	}

	/* Extract the expected hash from the manifest */
	memcpy(expected_hash, wrapper._COSE_Sign1_Manifest_payload_cbor
			._Manifest_blob_hash.value, sizeof(expected_hash));

	/* Calculate total length of all segments */
	blob_len = 0;
	for (int i = 0; i < segments._Segments__Segment_count; i++) {
		blob_len += segments._Segments__Segment[i]._Segment_len;
	}

	if (sizeof(hash) == wrapper._COSE_Sign1_Manifest_payload_cbor
			._Manifest_blob_hash.len) {
		hash_len_valid = true;
	} else {
		return -EINVAL;
	}

	err = get_hash_from_flash(fdev, blob_offset, blob_len, hash, buf,
				  buf_len);
	if (err != 0) {
		return err;
	}

	if (memcmp(expected_hash, hash, sizeof(hash)) == 0) {
		hash_valid = true;
	} else {
		return -EINVAL;
	}

	if (hash_len_valid && hash_valid) {
		return load_segments(fdev,
				meta_buf,
				wrapper_len,
				(const Segments_t *)&segments, blob_offset,
				buf);
	} else {
		return -EINVAL;
	}
}
