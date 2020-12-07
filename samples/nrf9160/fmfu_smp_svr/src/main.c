/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <zephyr.h>
#include <mgmt/mgmt_fmfu.h>
#include <mgmt/mgmt_fmfu_stat.h>
#include <modem/modem_info.h>
#include <modem/libmodem.h>
#include <modem/at_cmd.h>

void main(void)
{

	char modem_version[36];
	modem_info_init();
	modem_info_string_get(MODEM_INFO_FW_VERSION, modem_version, 36);
	printk("Starting modem mgmt sample\n\r");
	printk("Modem version: %s\n\r", modem_version);

	/* Shutdown modem to prepare for DFU */
	libmodem_shutdown();
	/* Register SMP Communication stats */
	mgmt_fmfu_stat_init();
	/* Initialize MCUMgr handlers for full modem update */
	int err = mgmt_fmfu_init();
	if (err) {
		printk("Error in init fmfu: %d\n\r", err);
	}
	printk("FMFU initialized ready to receive firmware\n\r");
	while (1) {
		k_cpu_idle();
	}
}

