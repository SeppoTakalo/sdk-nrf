/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdio.h>
#include <zephyr.h>
#include <sys/reboot.h>
#include <modem/nrf_modem_lib.h>
#include <sb_fota.h>

static void modem_fota_callback(enum sb_fota_event e)
{
	switch(e) {
	case FOTA_EVENT_DOWNLOADING:
		printk("Modem FOTA library: Checking for update\n");
		break;
	case FOTA_EVENT_IDLE:
		printk("Modem FOTA library: Idle\n");
		break;
	case FOTA_EVENT_MODEM_SHUTDOWN:
		printk("Modem FOTA library: Update downloaded. Modem will be updated.\n");
		break;
	case FOTA_EVENT_REBOOT_PENDING:
		printk("Modem FOTA library: Modem updated, need to reboot\n");
		sys_reboot(SYS_REBOOT_COLD);
		break;
	}
}

void main(void)
{
	int err;

	printk("Modem FOTA client started\n");

	err = nrf_modem_lib_get_init_ret();

	switch (err) {
	case MODEM_DFU_RESULT_OK:
		printk("Modem firmware update successful!\n");
		printk("Modem will run the new firmware after reboot\n");
		sys_reboot(SYS_REBOOT_WARM);
		break;
	case MODEM_DFU_RESULT_UUID_ERROR:
	case MODEM_DFU_RESULT_AUTH_ERROR:
		printk("Modem firmware update failed!\n");
		printk("Modem will run non-updated firmware on reboot.\n");
		sys_reboot(SYS_REBOOT_WARM);
		break;
	case MODEM_DFU_RESULT_HARDWARE_ERROR:
	case MODEM_DFU_RESULT_INTERNAL_ERROR:
		printk("Modem firmware update failed!\n");
		printk("Fatal error.\n");
		sys_reboot(SYS_REBOOT_WARM);
		break;
	case -1:
		printk("Could not initialize bsdlib.\n");
		printk("Fatal error.\n");
		return;
	default:
		break;
	}

	if (sb_fota_init(&modem_fota_callback) != 0) {
		printk("Failed to initialize modem FOTA\n");
		return;
	}

	k_sleep(K_FOREVER);
}
