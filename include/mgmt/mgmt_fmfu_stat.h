/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

/** @file mgmt_fmfu_stat.h
 * @defgroup mgmt_fmfu_stat Management Full Modem Firmware Upgrade Stats
 * @{
 * @brief Full Modem Firmware Update(FMFU) statistics.
 *
 * This registers a handler for the MCUMgr stat command to report back the
 * SMP protocol MTU and frame size.
 *
 */

#ifndef MGMT_FMFU_STAT_H__
#define MGMT_FMFU_STAT_H__

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Setup and register the module responsible for communicating SMP
 *	   buffer sizes.
 *
 *  This functions setups the stat group for mcumgr so that the serial modem
 *  module update script can negotiate the SMP protocol frame size.
 *
 *  @retval 0 on success, negative integer on failure.
 */
int mgmt_fmfu_stat_init(void);

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* MGMT_FMFU_STAT_H__ */
