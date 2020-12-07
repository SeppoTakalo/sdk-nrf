/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

/** @file mgmt_fmfu.h
 * @defgroup mgmt_fmfu Management Full Modem Firmware Upgrade 
 * @{
 * @brief Full Modem Firmware Update(FMFU).
 *
 * The Full Modem Firmware Upgrade (FMFU) provides function for configuring
 * MCUMgr to accept full modem update over the SMP protocol.
 *
 */

#ifndef MGMT_FMFU_H__
#define MGMT_FMFU_H__

#ifdef __cplusplus
extern "C" {
#endif


/* Define the buffer sizes used for smp server */
#define SMP_PACKET_MTU\
	CONFIG_MCUMGR_BUF_SIZE - \
	((CONFIG_UART_MCUMGR_RX_BUF_SIZE/CONFIG_MCUMGR_BUF_SIZE) + 1) * 4
#define SMP_UART_BUFFER_SIZE CONFIG_UART_MCUMGR_RX_BUF_SIZE


/** @brief Setup and register the full modem management group.
 *
 * This function requires that the libmodem_shutdown function has 
 * been called before initiated. 
 *
 * @retval 0 on success, negative integer on failure.
 */
int mgmt_fmfu_init(void);

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* MGMT_FMFU_H__ */
