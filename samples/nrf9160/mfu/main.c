/*
 * Copyright (c) 2012-2014 Wind River Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include "modem_mgmt.h"
#include "modem_mgmt_stat.h"

void main(void){
    modem_mgmt_stat_init();
    modem_mgmt_init();
    while (1) {
        k_cpu_idle();
    }
}

