/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <modem_update_decode.h>
#include <modem_update_encode.h>
#include <drivers/flash.h>
#include <logging/log.h>
#include <dfu/mfu_ext.h>
#include <ecdsa.h>
#include <sha256.h>

LOG_MODULE_REGISTER(mfu_ext, CONFIG_MFU_EXT_LOG_LEVEL);

#define MAX_META_LEN 0x400

static uint8_t *buf;
static size_t buf_len;

int mfu_ext_init(uint8_t *buf_in, size_t buf_len_in)
{
	if (buf_in == NULL) {
		return -EINVAL;
	}
	if (buf_len_in < MODEM_RPC_BUFFER_MIN_SIZE) {
		return -EINVAL;
	}

	buf = buf_in;
	buf_len = buf_len_in;

	return 0;
}

static int get_sig_structure(const COSE_Sign1_Manifest_t *wrapper, uint8_t *buf,
				size_t *buf_len)
{
	Sig_structure1_t sig_structure;
	bool result;

	memset(&sig_structure, 0, sizeof(sig_structure));
	memcpy(&(sig_structure._Sig_structure1_payload),
		&(wrapper->_COSE_Sign1_Manifest_payload),
		sizeof(sig_structure._Sig_structure1_payload));

	result = cbor_encode_Sig_structure1(buf, *buf_len, &sig_structure,
						buf_len);

	if (!result) {
		return -EINVAL;
	}

	return 0;
}

static int get_hash(const uint8_t *data, size_t data_len, uint8_t *hash)
{
	int err;
	mbedtls_sha256_context sha256_ctx;

	mbedtls_sha256_init(&sha256_ctx);

	err = mbedtls_sha256_starts_ret(&sha256_ctx, false);
	if (err != 0) {
		return err;
	}

	err = mbedtls_sha256_update_ret(&sha256_ctx, data, data_len);
	if (err != 0) {
		return err;
	}

	err = mbedtls_sha256_finish_ret(&sha256_ctx, hash);
	if (err != 0) {
		return err;
	}

	return 0;
}

static int get_hash_from_flash(const struct device *fdev, size_t offset,
				size_t data_len, uint8_t *hash,
				uint8_t * buffer, size_t buffer_len)
{
	int err;
	mbedtls_sha256_context sha256_ctx;
	size_t end = offset + data_len;

	mbedtls_sha256_init(&sha256_ctx);

	err = mbedtls_sha256_starts_ret(&sha256_ctx, false);
	if (err != 0) {
		return err;
	}

	for (size_t part_offs = offset; part_offs < end; part_offs += buffer_len) {
		size_t part_len = MIN(buffer_len, (end - part_offs));
		int err = flash_read(fdev, part_offs, buffer, part_len);

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

static int verify_signature(const uint8_t *signature, size_t sig_len,
				const uint8_t *hash, size_t hash_len,
				const uint8_t *pk, size_t pk_len)
{
	int err;
	mbedtls_mpi r;
	mbedtls_mpi s;
	mbedtls_ecdsa_context ctx;

	/* Prepare verification context. */
	mbedtls_ecdsa_init(&ctx);
	mbedtls_mpi_init( &r );
	mbedtls_mpi_init( &s );

	/* Get public EC information. */
	err = mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_SECP256R1);
	if (err != 0) {
		return err;
	}

	/* Get public key. */
	err = mbedtls_ecp_point_read_binary(&ctx.grp, &ctx.Q, pk, pk_len);
	if (err != 0) {
		return err;
	}

	/* Get signature. */
	err = mbedtls_mpi_read_binary(&r, signature, sig_len / 2);
	if (err != 0) {
		return err;
	}

	err = mbedtls_mpi_read_binary(&s, &signature[sig_len / 2], sig_len / 2);
	if (err != 0) {
		return err;
	}

	/* Verify the generated ECDSA signature by running the ECDSA verify. */
	err = mbedtls_ecdsa_verify(&ctx.grp, hash, hash_len, &ctx.Q, &r, &s);
	if (err != 0) {
		return err;
	}

	return 0;
}

static int prevalidate(const COSE_Sign1_Manifest_t *wrapper, const uint8_t *pk,
			size_t pk_len, uint8_t *buf, size_t buf_len)
{
	uint8_t hash[32];
	int err;

	err = get_sig_structure(wrapper, buf, &buf_len);
	if (err != 0) {
		return err;
	}

	err = get_hash(buf, buf_len, hash);
	if (err != 0) {
		return err;
	}

	err = verify_signature(wrapper->_COSE_Sign1_Manifest_signature.value,
				wrapper->_COSE_Sign1_Manifest_signature.len,
				hash, sizeof(hash), pk, pk_len);
	if (err != 0) {
		return err;
	}

	return 0;
}


static int get_blob_len(const uint8_t *segments_buf, size_t buf_len,
			size_t *segments_len)
{
	Segments_t segments;
	bool result;

	result = cbor_decode_Segments(segments_buf, buf_len, &segments, NULL);

	if (!result) {
		return -EINVAL;
	}

	*segments_len = 0;
	for (int i = 0; i < segments._Segments__Segment_count; i++) {
		*segments_len += segments._Segments__Segment[i]._Segment_len;
	}

	return 0;
}


#define MODEM_UPDATE_BUF_SIZE 0x400

extern uint8_t mfu_pk[65];

int mfu_ext_prevalidate(const struct device *fdev, size_t offset, bool *valid,
			uint32_t *seg_offset, uint32_t *blob_offset)
{
	uint8_t hash[32];
	uint8_t expected_hash[32];
	bool sig_valid = false;
	bool hash_len_valid = false;
	bool hash_valid = false;
	COSE_Sign1_Manifest_t wrapper;
	const cbor_string_type_t *segments_string;
	size_t segments_offs;
	int err;
	bool result;
	size_t seg_start, blob_len;

	*valid = false;

	err = flash_read(fdev, offset, buf, MAX_META_LEN);

	if (err != 0) {
		return err;
	}

	result = cbor_decode_Wrapper(buf, MAX_META_LEN, &wrapper, blob_offset);

	if (!result) {
		return -EINVAL;
	}

	*blob_offset += offset;
	seg_start = *blob_offset;
	segments_string = &wrapper._COSE_Sign1_Manifest_payload_cbor
			._Manifest_segments;
	segments_offs = offset + (size_t)segments_string->value - (size_t)buf;
	memcpy(expected_hash, wrapper._COSE_Sign1_Manifest_payload_cbor
			._Manifest_blob_hash.value, sizeof(expected_hash));

	err = get_blob_len(segments_string->value, segments_string->len,
				&blob_len);
	if (err != 0) {
		return err;
	}

	err = prevalidate(&wrapper, mfu_pk, sizeof(mfu_pk), &buf[MAX_META_LEN],
				MAX_META_LEN);
	if (err == 0) {
		sig_valid = true;
	} else {
		return err;
	}

	if (sizeof(hash) == wrapper._COSE_Sign1_Manifest_payload_cbor
			._Manifest_blob_hash.len) {
		hash_len_valid = true;
	} else {
		return -EINVAL;
	}

	err = get_hash_from_flash(fdev, *blob_offset, blob_len, hash, buf, buf_len);
	if (err != 0) {
		return err;
	}

	// TODO: Use constant time variant.
	if (0 == memcmp(expected_hash, hash, sizeof(hash))) {
		hash_valid = true;
	} else {
		return -EINVAL;
	}

	if (sig_valid && hash_len_valid && hash_valid) {
		*valid = true;
		*seg_offset = segments_offs;
		return 0;
	} else {
		return -EINVAL;
	}
}


static int load_segment(const struct device *fdev, size_t seg_size,
			uint32_t seg_addr)
{
	struct memory_chunk chunk = {.data = buf};
	size_t bytes_left = seg_size;
	uint32_t read_addr = seg_addr;
	int err;

	while (bytes_left) {
		uint32_t read_len = MAX(RPC_BUFFER_SIZE, bytes_left);
		err = flash_read(fdev, read_addr, buf, read_len);
		if (err != 0) {
			LOG_ERR("flash_read failed2: %d", err);
			return err;
		}

		chunk.data_len = read_len;
		chunk.target_address = seg_addr + \
				       (seg_size - bytes_left - read_len);

		err = mfu_stream_chunk(&chunk);
		if (err != 0) {
			LOG_ERR("mfu_stream failed: %d", err);
			return err;
		}

		bytes_left -= read_len;
		read_addr += read_len;
	}

	return 0;
}

int mfu_ext_load(const struct device *fdev, size_t seg_offset, size_t blob_offset)
{
	int err;
	Segments_t seg;
	size_t prev_segments_len = 0;
	bool result;

	if (fdev == NULL) {
		return -EINVAL;
	}

	err = flash_read(fdev, seg_offset, buf, MAX_META_LEN);
	if (err != 0) {
		LOG_ERR("flash_read failed1: %d", err);
		return err;
	}

	result = cbor_decode_Segments(buf, MAX_META_LEN, &seg, NULL);
	if (!result) {
		LOG_ERR("cbor_decode_Segments failed");
		return -EINVAL;
	}

	for (int i = 0; i < seg._Segments__Segment_count; i++) {
		size_t seg_size = seg._Segments__Segment[i]._Segment_len;
		uint32_t seg_addr = blob_offset + prev_segments_len;

		err = load_segment(fdev, seg_size, seg_addr);
		if (err != 0) {
			LOG_ERR("load_segment failed: %d", err);
			return err;
		}

		err = mfu_stream_end();
		if (err != 0) {
			LOG_ERR("mfu_stream_end failed: %d", err);
			return err;
		}

		prev_segments_len += seg_size;
	}

	return 0;

}

