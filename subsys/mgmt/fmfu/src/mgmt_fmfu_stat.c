/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */


#include <zephyr.h>
#include <stats/stats.h>
#include <mgmt/mgmt_fmfu.h>
#include <mgmt/mgmt_fmfu_stat.h>

STATS_SECT_START(smp_com_param)
STATS_SECT_ENTRY(frame_max)
STATS_SECT_ENTRY(pack_max)
STATS_SECT_END;

/* Assign a name to each stat. */
STATS_NAME_START(smp_com_param)
STATS_NAME(smp_com_param, frame_max)
STATS_NAME(smp_com_param, pack_max)
STATS_NAME_END(smp_com_param);

/* Define an instance of the stats group. */
STATS_SECT_DECL(smp_com_param) smp_com_param;

int mgmt_fmfu_stat_init(void)
{
	/* Register/start the stat service */
	stat_mgmt_register_group();

	int rc = STATS_INIT_AND_REG(smp_com_param, STATS_SIZE_32, "smp_com");

	STATS_INCN(smp_com_param, frame_max, SMP_UART_BUFFER_SIZE);
	STATS_INCN(smp_com_param, pack_max, SMP_PACKET_MTU);
	
	return rc;
}
