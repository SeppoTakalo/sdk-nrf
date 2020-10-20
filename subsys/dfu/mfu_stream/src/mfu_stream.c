/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <zephyr.h>
#include <logging/log.h>
#include "cborattr/cborattr.h"
#include "modem_dfu_rpc.h"
#include "mgmt_mfu.h"

LOG_MODULE_REGISTER(mfu, CONFIG_DFU_TARGET_LOG_LEVEL);

modem_state_t modem_get_state(void){
    return status.modem_state;
}

static uint8_t rpc_buf[RPC_BUFFER_SIZE];

int mfu_stream_init(void)
{
	int err;
	static bool initialized;
	modem_digest_buffer_t buf;

	if (initialized) {
		return 0;
	}

	err = modem_rpc_init(&buf, rpc_buf, sizeof(rpc_buf));
	if (err != 0) {
		LOG_ERR("modem_rpc_init failed: %d", err);
		return err;
	}

	if (modem_get_state() != MODEM_STATE_WAITING_FOR_BOOTLOADER) {
		LOG_ERR("modem_rpc not in correct state");
		return -EFAULT;
	}

	initialized = true;

	return 0;
}


int mfu_stream_chunk(const modem_memory_chunk_t *chunk)
{
	int err;

        switch (modem_get_state()){
            case MODEM_STATE_WAITING_FOR_BOOTLOADER:
                err = modem_write_bootloader_chunk(chunk);
                break;
            case MODEM_STATE_READY_FOR_IPC_COMMANDS:
                err = modem_write_firmware_chunk(chunk);
                break;
            default:
                return MGMT_ERR_EBADSTATE;
        }

	return err;
}

int mfu_stream_end(void) {
	return modem_end_transfer();
}
