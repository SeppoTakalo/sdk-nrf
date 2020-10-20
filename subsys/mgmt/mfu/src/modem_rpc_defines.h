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

#ifndef __MODEM_RPC_DEFINES_H__
#define __MODEM_RPC_DEFINES_H__

// Commands
#define MODEM_RPC_CMD_PROGRAM_RANGE         0x00000003ul
#define MODEM_RPC_CMD_DIGEST_RANGE          0x00000007ul
#define MODEM_RPC_CMD_READ_UUID             0x00000008ul

// Error response
#define MODEM_RPC_RESP_UNKNOWN_CMD          0x5A000001ul
#define MODEM_RPC_RESP_CMD_ERROR            0x5A000002ul

// Response
#define MODEM_RPC_RESP_ROOT_KEY_DIGEST      0xA5000001ul
#define MODEM_RPC_RESP_PROGRAM_RANGE        0xA5000005ul
#define MODEM_RPC_RESP_DIGEST_RANGE         0xA5000007ul
#define MODEM_RPC_RESP_READ_UUID            0xA5000008ul

#define MODEM_RPC_RESP_STATUS_OK            0x00000001ul
#define MODEM_RPC_RESP_STATUS_FAIL          0xFFFFFFFFul  ///< -1

// Used for when you don't expect a response
#define MODEM_RPC_RESP_NONE                 0x00000000ul

// Digest range defines
#define MODEM_RPC_MAX_DIGEST_RANGE_BYTES    0x10000
#define MODEM_RPC_MIN_DIGEST_RANGE_BYTES    16

typedef struct __attribute__ ((__packed__))
{
    uint32_t    version;        /**< RPC version */
    uint32_t    shmem_start;    /**< Start address of shared memory region dedicated for the DFU usage */
    uint32_t    shmem_size;     /**< Size of shared memory region reserved for DFU usage */
} modem_rpc_descriptor_t;

typedef struct
{
    uint32_t  id;
    uint32_t  param[];
} modem_rpc_cmd_t;

typedef struct
{
    uint32_t  id;
    uint32_t  start;
    uint32_t  bytes;
    uint32_t  data[];
} modem_rpc_program_cmd_t;

typedef struct
{
  uint32_t start;
  uint32_t bytes;
} modem_rpc_digest_range_t;

typedef struct
{
    uint32_t                  id;
    uint32_t                  no_ranges;
    modem_rpc_digest_range_t  ranges[];
} modem_rpc_digest_cmd_t;

typedef struct
{
    uint32_t  id;
    uint32_t  payload[];
} modem_rpc_response_t;

#endif /* __MODEM_RPC_DEFINES_H__ */
