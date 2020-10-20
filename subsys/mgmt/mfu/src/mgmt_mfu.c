/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <zephyr.h>
#include <logging/log.h>
#include "mgmt/mgmt.h"
#include "cborattr/cborattr.h"
#include "modem_dfu_rpc.h"
#include <stats/stats.h>
#include "mgmt_mfu.h"

LOG_MODULE_REGISTER(mgmt_mfu, CONFIG_MGMT_MFU_LOG_LEVEL);

#define MODEM_MGMT_ID_GET_HASH 0
#define MODEM_MGMT_ID_UPLOAD 1

uint8_t buf[SMP_PACKET_MAXIMUM_TRANSMISSION_UNIT];

static int get_mgmt_err_from_modem_ret_err(modem_err_t modem_error_return){
	switch(modem_error_return){
		case MODEM_RET_RPC_COMMAND_FAILED:
			return MGMT_ERR_EMODEM_INVALID_COMMAND;
		case MODEM_RET_RPC_COMMAND_FAULT:
			return MGMT_ERR_EMODEM_FAULT;
		default:
			return MGMT_ERR_EBADSTATE;
	}
}

void modem_mgmt_init(void){
	mgmt_register_group(&modem_mgmt_group);
	return mfu_stream_init();
}

static int encode_response(struct mgmt_ctxt *ctx, uint32_t expected_offset) {
	int err;

	/* TODO should we return this after the whole file has been received?*/
	err |= cbor_encode_text_stringz(&ctxt->encoder, "rc");
	err |= cbor_encode_int(&ctxt->encoder, status);
	err |= cbor_encode_text_stringz(&ctxt->encoder, "off");
	err |= cbor_encode_uint(&ctxt->encoder, expected_offset);

	if (err != 0) {
		return MGMT_ERR_ENOMEM;
	}

	return 0;
}

static int modem_mgmt_firmware_upload(struct mgmt_ctxt *ctxt)
{
	int err;
	int ret;
	bool whole_file_received;
	static modem_memory_chunk_t chunk = {.data = buf}
	uint32_t next_expected_offset;
	CborError err;

	ret = unpack(ctxt, &firmware_packet, &next_expected_offset,
		     &whole_file_received);
	if (ret < 0){
		return ret;
	} else {
		next_expected_offset = ret;
	}

	if (firmware_packet.chunk.data_len > 0) {
		err = mfu_stream(firmware_packet.chunk);
		if (err != 0){
			return get_mgmt_err_from_modem_ret_err(err);
		}
	}

	if (whole_file_received) {
		err = mfu_stream_end();
		if (err != 0){
			return get_mgmt_err_from_modem_ret_err(err);
		}
	}

	return encode_response(ctx, next_expected_offset);
}

static int modem_mgmt_get_memory_hash(struct mgmt_ctxt * ctxt){
	unsigned long long start;
	unsigned long long end;

	/* We expect two variables: the start and end address of a memory region
	 * that we want to verify (obtain a hash for) */
	const struct cbor_attr_t off_attr[] = {
		[0] = {
			.attribute = "start",
			.type = CborAttrUnsignedIntegerType,
			.addr.uinteger = &start,
			.nodefault = true
		},
		[1] = {
			.attribute = "end",
			.type = CborAttrUnsignedIntegerType,
			.addr.uinteger = &end,
			.nodefault = true
		},
		[2] = { 0 },
	};
	start = 0;
	end = 0;

	/* Parse JSON object */
	int rc = cbor_read_object(&ctxt->it, off_attr);
	if (rc || start == 0 || end == 0) {
		return MGMT_ERR_EINVAL;
	}

	/* Try to request the memory range digest from the modem */
	modem_digest_buffer_t digest_buffer;
	modem_err_t err = modem_get_memory_hash(start, end, &digest_buffer);
	if (err != MODEM_RET_SUCCESS){
		return get_mgmt_err_from_modem_ret_err(err);
	}

	/* Put the digest response in the response */
	CborError cbor_err = 0;
	cbor_err |= cbor_encode_text_stringz(&ctxt->encoder, "digest");
	cbor_err |= cbor_encode_byte_string(&ctxt->encoder,
			(uint8_t *)digest_buffer.data, MODEM_DIGEST_BUFFER_LEN);
	cbor_err |= cbor_encode_text_stringz(&ctxt->encoder, "rc");
	cbor_err |= cbor_encode_int(&ctxt->encoder, err);
	if (cbor_err != 0) {
		return MGMT_ERR_ENOMEM;
	}

	return MGMT_ERR_EOK;
}

static int unpack(struct mgmt_ctxt *ctxt, modem_memory_chunk_t* chunk,
		  bool *whole_file_received){
	int err;
	uint32_t file_length;
	uint32_t offset;

	/* Description/skeleton of CBOR object */
	const struct cbor_attr_t off_attr[] = {
		[0] = {
			.attribute = "data",
			.type = CborAttrByteStringType,
			.addr.bytestring.data = chunk->data,
			.addr.bytestring.len = &chunk->data_len,
			.len = SMP_PACKET_MAXIMUM_TRANSMISSION_UNIT
		},
		[2] = {
			.attribute = "off",
			.type = CborAttrUnsignedIntegerType,
			.addr.uinteger = &offset,
			.nodefault = true
		},
		[4] = {
			.attribute = "addr",
			.type = CborAttrUnsignedIntegerType,
			.addr.uinteger = &chunk->target_address,
			.nodefault = true
		},
		/* TODO get file length */
		[6] = { 0 },
	};

	err = cbor_read_object(&ctxt->it, off_attr);
	if (err) {
		return -MGMT_ERR_EINVAL;
	}

	*whole_file_received = offset == file_length;

	return offset + chunk->data_len;
}

static struct mgmt_group modem_mgmt_group = {
	.mg_handlers = (struct mgmt_handler *)mgmt_mfu_handlers,
	.mg_handlers_count = ARRAY_SIZE(mgmt_mfu_handlers),
	.mg_group_id = (MGMT_GROUP_ID_PERUSER + 1),
};

static const struct mgmt_handler mgmt_mfu_handlers[] = {
	[MODEM_MGMT_ID_GET_HASH] = {
		.mh_read  = modem_mgmt_get_memory_hash,
		.mh_write = modem_mgmt_get_memory_hash,
	},
	[MODEM_MGMT_ID_UPLOAD] = {
		.mh_read  = NULL,
		.mh_write = modem_mgmt_firmware_upload
	},
};
