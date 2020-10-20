/* Copyright (c) 2010 - 2020, Nordic Semiconductor ASA
 * 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form, except as embedded into a Nordic
 *    Semiconductor ASA integrated circuit in a product or a software update for
 *    such product, must reproduce the above copyright notice, this list of
 *    conditions and the following disclaimer in the documentation and/or other
 *    materials provided with the distribution.
 * 
 * 3. Neither the name of Nordic Semiconductor ASA nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 * 
 * 4. This software, with or without modification, must only be used with a
 *    Nordic Semiconductor ASA integrated circuit.
 * 
 * 5. Any software provided in binary form under this license must not be reverse
 *    engineered, decompiled, modified and/or disassembled.
 * 
 * THIS SOFTWARE IS PROVIDED BY NORDIC SEMICONDUCTOR ASA "AS IS" AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY, NONINFRINGEMENT, AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL NORDIC SEMICONDUCTOR ASA OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */

#include "modem_mgmt_stat.h"
#include "modem_mgmt.h"
#include <zephyr.h>
#include <stats/stats.h>
#include "stat_mgmt/stat_mgmt.h"

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

void modem_mgmt_stat_init(void){
    /* Register/start the stat service */
    stat_mgmt_register_group();

    int rc;
    rc = STATS_INIT_AND_REG(smp_com_param, STATS_SIZE_32 , "smp_com");
    STATS_INCN( smp_com_param, frame_max, SMP_UART_BUFFER_SIZE);
    STATS_INCN( smp_com_param, pack_max, SMP_PACKET_MAXIMUM_TRANSMISSION_UNIT);
}
