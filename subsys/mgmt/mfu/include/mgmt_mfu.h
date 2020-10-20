/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#ifndef MGMT_MFU_H__
#define MGMT_MFU_H__

/* Define modem mgmt spesific SMP return codes */
#define MGMT_ERR_EMODEM_INVALID_COMMAND 200
#define MGMT_ERR_EMODEM_FAULT           201

/* Define the buffer sizes used for smp server */
#define SMP_PACKET_MAXIMUM_TRANSMISSION_UNIT \
	CONFIG_MCUMGR_BUF_SIZE - \
	((CONFIG_UART_MCUMGR_RX_BUF_SIZE/CONFIG_MCUMGR_BUF_SIZE) + 1) * 4
#define SMP_UART_BUFFER_SIZE CONFIG_UART_MCUMGR_RX_BUF_SIZE

void mgmt_mfu_init(void);

#endif /* MGMT_MFU_H__ */
