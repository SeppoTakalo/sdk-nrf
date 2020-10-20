/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

/** @file
 * @brief Modem Firmware Upgrade Stream header.c
 */


#ifndef MFU_STREAM_H__
#define MFU_STREAM_H__

/**
 * @defgroup mfu_stream Modem Firmware Update Stream
 * @{
 *
 * The Modem Firmware Update (MFU) Stream provides funtions for writing
 * modem firmware to the MFU library.
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

/* TODO #include <modem_dfu_rpc.h> */

/* TODO replace with proper */
#define MODEM_RPC_BUFFER_MIN_SIZE (8*1024)
#define RPC_BUFFER_SIZE (MODEM_RPC_BUFFER_MIN_SIZE)

struct memory_chunk {
    uint32_t target_address;
    uint32_t data_len;
    uint8_t *data;
};

/**
 * @brief End MFU stream. Must be called after last chunk is streamed.
 *
 * @return Non-negative value for success, negative error code if it fails.
 *
 **/
int mfu_stream_end(void);

/**
 * @brief Write a chunk of modem firmware to the MFU library.
 *
 * @param[in] chunk The chunk of data to write.
 *
 * @return Non-negative value for success, negative error code if it fails.
 *
 **/
int mfu_stream_chunk(const struct memory_chunk *chunk);


#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* MFU_STREAM_H__ */
