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

#include "modem_dfu_rpc.h"
#include "modem_rpc_defines.h"
#include <nrf.h>

/* Initialize the logger for this file */
#define LOG_LEVEL LOG_LEVEL_DBG
#define LOG_MODULE_NAME modem_dfu_rpc
#include <logging/log.h>
LOG_MODULE_REGISTER();

#define UPPER_HALF_OF_RAM_START_ADDRESS 0x20020000

/* IPC related defines */
#define VMC_RAM_BLOCKS                    8
#define VMC_RAM_SECTIONS_PER_BLOCK        4
#define IPCEVENT_FAULT_RECEIVE_CHANNEL    0
#define IPCEVENT_COMMAND_RECEIVE_CHANNEL  2
#define IPCEVENT_DATA_RECEIVE_CHANNEL     4
#define IPCTASK_DATA_SEND_CHANNEL         1
#define IPC_WAIT_FOR_EVENT_TIME_MS        2000


#ifdef MODEM_DFU_RPC_USE_SYSTICK
/* Systick underflow will happen every 10ms when the timer is running, which will update the count flag in SysTick->CTRL
 * This implies the wait time IPC_WAIT_FOR_EVENT_TIME_MS has a resolution of 10ms */
#define SYSTICK_MAX_UNDERFLOW_COUNT       (IPC_WAIT_FOR_EVENT_TIME_MS / 10)

static void         modem_rpc_systick_init(void);
static void         modem_rpc_systick_start(void);
static void         modem_rpc_systick_stop(void);
static void         modem_rpc_systick_wait_tenms(uint32_t num_of_tenms);

static uint32_t systick_underflow_count = 0;

static void wait_ms(uint32_t ms){
    modem_rpc_systick_wait_tenms(ms/10);
}


/* SysTick is used as an inaccurate timer for detecting timeout of the modem response during RPC operation */
static void modem_rpc_systick_init(void){
    modem_rpc_systick_stop();

    /* Use the 10ms calibration value if it is set,
     * We don't care about the SKEW flag */
    if (SysTick->CALIB & SysTick_CALIB_TENMS_Msk){
        SysTick->LOAD = SysTick->CALIB & SysTick_LOAD_RELOAD_Msk;
    }
    /* If calibration is not available, calculate from core clock frequency */
    else{
        SysTick->LOAD = ((SystemCoreClock / 100) - 1) & SysTick_LOAD_RELOAD_Msk;
    }
}


static void modem_rpc_systick_start(void){
    /* The count flag in the SysTick->CTRL register is cleared when writing to SysTick->VAL */
    SysTick->VAL              = 0;
    systick_underflow_count   = 0;
    SysTick->CTRL             = (1 << SysTick_CTRL_ENABLE_Pos);
}


static void modem_rpc_systick_stop(void){
    /* Disable SysTick and clear the 'count' flag */
    SysTick->CTRL &= ~(1 << SysTick_CTRL_ENABLE_Pos);
}


/* Function for doing a busy-wait for approximately (num_of_tenms * 10ms) */
static void modem_rpc_systick_wait_tenms(uint32_t num_of_tenms){
    modem_rpc_systick_start();
    while(!(SysTick->CTRL & SysTick_CTRL_COUNTFLAG_Msk)){};
    modem_rpc_systick_stop();
}
#else
#include <zephyr.h>
static void wait_ms(uint32_t ms){
    // TODO k_sleep((k_timeout_t)ms);
}

#endif

/* Forward declaration of local (static) functions */
static void         modem_ipc_init(void);
static void         modem_ipc_clear_events(void);
static modem_err_t  modem_ipc_wait_for_event(void);
static modem_err_t  modem_ipc_trigger_and_check_response(uint32_t expected_response);
static modem_err_t  modem_prepare_for_dfu(modem_digest_buffer_t * digest_buffer);

/* There are multiple definitions of the header bytes used in the RPC protocol, depending on the type of command.
 * This is why different structs are used to keep track of the byte field names */
union dfu_modem_com_t{
    volatile modem_rpc_cmd_t            cmd;
    volatile modem_rpc_program_cmd_t    program;
    volatile modem_rpc_digest_cmd_t     digest;
    volatile modem_rpc_response_t       response;
    volatile uint8_t                    buffer[1]; /* Buffer is of unknown length at program start. The [1] is a placeholder. */
};

static volatile union dfu_modem_com_t * rpc_buffer    = NULL;
static uint32_t rpc_buffer_total_size        = 0;
static uint32_t rpc_buffer_payload_size      = 0;

/* The "descriptor" struct defines the API version and buffer location (of rpc_buffer)
 * for the Remote Procedure Call communication. This struct is handed to the modem when initializing */
static modem_rpc_descriptor_t descriptor = {
  .version      = 0x80010000,
  .shmem_start  = (uint32_t)NULL,
  .shmem_size   = 0
};

/* Struct for tracking the state of the modem and firmware upload progress */
typedef struct {
    modem_state_t       modem_state;
    unsigned long long  rpc_data_target_address;
    unsigned long long  rpc_offset_in_buffer;
} status_t;

static status_t status = {
    .modem_state                  = MODEM_STATE_UNINITIALIZED,
    .rpc_data_target_address      = 0,
    .rpc_offset_in_buffer         = 0,
};


modem_state_t modem_get_state(void){
    return status.modem_state;
}


/* Helping function for entering modem bad state */
static void set_modem_state_bad(void){
    status.modem_state = MODEM_STATE_BAD;
}


/* Main initialization function for this module
 * Init configures IPC, shared RAM, and attempts to put modem in DFU mode */
modem_err_t modem_dfu_rpc_init(modem_digest_buffer_t * digest_buffer, uint8_t* modem_rpc_buffer, uint32_t modem_rpc_buffer_length){

    /* Disallow buffers that span into the upper half of App RAM */
    uint32_t end_of_buffer_address = (uint32_t)(modem_rpc_buffer) + modem_rpc_buffer_length - 1;
    if (end_of_buffer_address >= UPPER_HALF_OF_RAM_START_ADDRESS){
        return MODEM_RET_INVALID_ARGUMENT;
    }

    /* Check if buffer is too small */
    if (modem_rpc_buffer_length < MODEM_RPC_BUFFER_MIN_SIZE){
        return MODEM_RET_INVALID_ARGUMENT;
    }

    /* Find total buffer size to use. It must follow the form (0xC + n*PAGE_SIZE) */
    uint32_t rpc_buffer_num_pages =  (modem_rpc_buffer_length - MODEM_RPC_OVERHEAD_SIZE) / MODEM_RPC_PAGE_SIZE;
    rpc_buffer_total_size = MODEM_RPC_OVERHEAD_SIZE + (rpc_buffer_num_pages * MODEM_RPC_PAGE_SIZE);

    /* Enforce max limit */
    if (modem_rpc_buffer_length > MODEM_RPC_BUFFER_MAX_SIZE){
        rpc_buffer_total_size = MODEM_RPC_BUFFER_MAX_SIZE;
    }

    /* Update payload size (total - overhead) */
    rpc_buffer_payload_size = rpc_buffer_total_size - MODEM_RPC_OVERHEAD_SIZE;

    /* Set rpc_buffer to point to given buffer */
    rpc_buffer = (union dfu_modem_com_t *)(modem_rpc_buffer);

    if (rpc_buffer_total_size != modem_rpc_buffer_length){
        LOG_WRN("The modem DFU RPC buffer has %uB unused space (not page aligned)\r\n", modem_rpc_buffer_length - rpc_buffer_total_size);
    }

    // Reset status
    status.modem_state                  = MODEM_STATE_UNINITIALIZED;
    status.rpc_data_target_address      = 0;
    status.rpc_offset_in_buffer         = 0;

    #ifdef MODEM_DFU_RPC_USE_SYSTICK
    modem_rpc_systick_init();
    #endif

    modem_ipc_init();
    return modem_prepare_for_dfu(digest_buffer);
}


static void modem_ipc_init(void){
    #ifndef NRF_TRUSTZONE_NONSECURE
        /* Configure APP IPC as non-secure */
        NRF_SPU_S->PERIPHID[IPC_IRQn].PERM = 0;

        /* Configure APP RAM to non-secure */
        const uint32_t num_ram_regions = VMC_RAM_BLOCKS * VMC_RAM_SECTIONS_PER_BLOCK;
        const uint32_t perm_read_write_excecute = 0x7;

        for (uint32_t ramregion = 0; ramregion < num_ram_regions; ramregion++){
            NRF_SPU_S->RAMREGION[ramregion].PERM = perm_read_write_excecute;
        }
    #endif

    /* Enable brodcasting on IPC channel 1 and 3 */
    NRF_IPC_NS->SEND_CNF[1] = (IPC_SEND_CNF_CHEN1_Enable << IPC_SEND_CNF_CHEN1_Pos);
    NRF_IPC_NS->SEND_CNF[3] = (IPC_SEND_CNF_CHEN3_Enable << IPC_SEND_CNF_CHEN3_Pos);

    /* Send rpc descriptor memory address to slave MCU via IPC */
    NRF_IPC_NS->GPMEM[0] = (uint32_t)&descriptor | 0x01000000ul;

    /* Reset fault indication */
    NRF_IPC_NS->GPMEM[1] = 0;

    /* Enable subscription to relevant channels */
    NRF_IPC_NS->RECEIVE_CNF[IPCEVENT_FAULT_RECEIVE_CHANNEL]     = (1 << IPCEVENT_FAULT_RECEIVE_CHANNEL);
    NRF_IPC_NS->RECEIVE_CNF[IPCEVENT_COMMAND_RECEIVE_CHANNEL]   = (1 << IPCEVENT_COMMAND_RECEIVE_CHANNEL);
    NRF_IPC_NS->RECEIVE_CNF[IPCEVENT_DATA_RECEIVE_CHANNEL]      = (1 << IPCEVENT_DATA_RECEIVE_CHANNEL);

    modem_ipc_clear_events();
}


static modem_err_t modem_prepare_for_dfu(modem_digest_buffer_t * digest_buffer){

    modem_ipc_clear_events();

    /* Store DFU indication into shared memory */
    descriptor.version        = 0x80010000;
    descriptor.shmem_start    = (uint32_t)(rpc_buffer) | 0x01000000ul;
    descriptor.shmem_size     = rpc_buffer_total_size;

    #ifndef NRF_TRUSTZONE_NONSECURE
    wait_ms(10);
    *((uint32_t *)0x50005610) = 0;
    wait_ms(10);
    *((uint32_t *)0x50005610) = 1;
    wait_ms(10);
    *((uint32_t *)0x50005610) = 0;
    wait_ms(10);
    #else
    wait_ms(10);
    *((uint32_t *)0x40005610) = 0;
    wait_ms(10);
    *((uint32_t *)0x40005610) = 1;
    wait_ms(10);
    *((uint32_t *)0x40005610) = 0;
    wait_ms(10);
    #endif

    /* Start polling IPC.MODEM_CTRL_EVENT to receive root key digest */
    modem_err_t err = modem_ipc_wait_for_event();
    if (err != MODEM_RET_SUCCESS){
        LOG_ERR("Error received when waiting for IPC event from the modem in modem DFU init\r\n");
        set_modem_state_bad();
        return err;
    }

    /* Check response field */
    if (rpc_buffer->response.id != MODEM_RPC_RESP_ROOT_KEY_DIGEST){
        LOG_ERR("Bootloader root key digest response not found in RPC buffer during modem dfu init\n\r");
        set_modem_state_bad();
        return MODEM_RET_RPC_UNEXPECTED_RESPONSE;
    }

    /* Copy rootkey/bootloader digest */
    memcpy(digest_buffer->data, (uint8_t *)(rpc_buffer->response.payload), MODEM_DIGEST_BUFFER_LEN);

    /* Update the dfu state. After the modem reset, a bootloader must be programmed */
    status.modem_state = MODEM_STATE_WAITING_FOR_BOOTLOADER;
    return MODEM_RET_SUCCESS;
}


static void modem_ipc_clear_events(void){
    NRF_IPC_NS->EVENTS_RECEIVE[IPCEVENT_COMMAND_RECEIVE_CHANNEL]  = 0;
    NRF_IPC_NS->EVENTS_RECEIVE[IPCEVENT_DATA_RECEIVE_CHANNEL]     = 0;
    NRF_IPC_NS->EVENTS_RECEIVE[IPCEVENT_FAULT_RECEIVE_CHANNEL]    = 0;
}


static modem_err_t modem_ipc_wait_for_event(void){
    bool got_event = false;
    modem_err_t err = MODEM_RET_SUCCESS;

    #ifdef MODEM_DFU_RPC_USE_SYSTICK
    modem_rpc_systick_start();
    while(systick_underflow_count < SYSTICK_MAX_UNDERFLOW_COUNT){
        if (SysTick->CTRL & SysTick_CTRL_COUNTFLAG_Msk) {
            ++systick_underflow_count;
        }
    #else
    size_t start_time = k_uptime_get();
    size_t compare_time = start_time;
    while(k_uptime_delta(&compare_time) < IPC_WAIT_FOR_EVENT_TIME_MS){
        /* k_uptime_delta will update the time value held by the input argument, so we need to reset it to the start time */
        compare_time = start_time;
    #endif

        if (NRF_IPC_NS->EVENTS_RECEIVE[IPCEVENT_COMMAND_RECEIVE_CHANNEL] || NRF_IPC_NS->EVENTS_RECEIVE[IPCEVENT_DATA_RECEIVE_CHANNEL]){
            got_event = true;
            break;
        }
        if (NRF_IPC_NS->EVENTS_RECEIVE[IPCEVENT_FAULT_RECEIVE_CHANNEL]){
            LOG_ERR("Modem signaled error on IPC channel. GPMEM[1]: 0x%08X\n\r", NRF_IPC_NS->GPMEM[1]);
            err = MODEM_RET_IPC_FAULT_EVENT;
            break;
        }
    }

    #ifdef MODEM_DFU_RPC_USE_SYSTICK
    modem_rpc_systick_stop();
    #endif

    modem_ipc_clear_events();

    /* Got error */
    if (err != MODEM_RET_SUCCESS){
        return err;
    }

    /* Got timeout */
    if (!got_event){
        LOG_ERR("Timed out when waiting for IPC event from modem\r\n");
        return MODEM_RET_RPC_TIMEOUT;
    }

    return MODEM_RET_SUCCESS;
}


static modem_err_t modem_ipc_trigger_and_check_response(uint32_t expected_response){
    LOG_DBG("Trigger IPC event\n\r");

    /* Trigger ipc and check for timeout. */
    modem_ipc_clear_events();
    NRF_IPC_NS->TASKS_SEND[IPCTASK_DATA_SEND_CHANNEL] = 1;

    modem_err_t err = modem_ipc_wait_for_event();
    if (err != MODEM_RET_SUCCESS){
        return err;
    }

    /* Check the rpc command return value for errors (placed by the modem in shared memory) */
    switch (rpc_buffer->response.id)
    {
        case MODEM_RPC_RESP_UNKNOWN_CMD:
            LOG_DBG("\tReceived MODEM_RPC_RESP_UNKNOWN_CMD.\n\r");
            return MODEM_RET_RPC_COMMAND_FAULT;
        case MODEM_RPC_RESP_CMD_ERROR:
            LOG_DBG("\tReceived MODEM_RPC_RESP_CMD_ERROR.\n\r");
            return MODEM_RET_RPC_COMMAND_FAILED;
        default:
            break;
    }

    /* Check if the value matches expected value (if applicable) */
    if (rpc_buffer->response.id != expected_response && expected_response != MODEM_RPC_RESP_NONE){
        LOG_DBG("\tReceived unexpected response value: 0x%08X\n\r", rpc_buffer->response.id);
        return MODEM_RET_RPC_UNEXPECTED_RESPONSE;
    }

    LOG_DBG("\tReceived ACK_OK.\n\r");
    return MODEM_RET_SUCCESS;
}


static void modem_rpc_program_write_metadata(uint32_t address, uint32_t size){
    LOG_DBG("Write RPC data output:\n\r");
    LOG_DBG("\tid:    IPC_DFU_CMD_PROGRAM_RANGE \n\r");
    LOG_DBG("\tstart: 0x%08X\n\r", address);
    LOG_DBG("\tbytes: 0x%08X\n\r", size);
    rpc_buffer->program.id    = MODEM_RPC_CMD_PROGRAM_RANGE;
    rpc_buffer->program.start = address;
    rpc_buffer->program.bytes = size;
}


modem_err_t modem_write_bootloader_chunk(modem_memory_chunk_t * bootloader_chunk){
    /* Check if the current state allows programming bootloader */
    if (status.modem_state != MODEM_STATE_WAITING_FOR_BOOTLOADER){
        return MODEM_RET_INVALID_OPERATION;
    }

    /* Check current offset position. We must be able to fit the entire bootloader into the RPC buffer */
    if ((status.rpc_offset_in_buffer + bootloader_chunk->data_len) > rpc_buffer_payload_size){
        LOG_ERR("Modem bootloader too large for RPC buffer.");
        return MODEM_RET_INVALID_ARGUMENT;
    }

    /* Write data chunk to RPC buffer with given offset
     * No spesific RPC instruction is used, e.g. the bootloader is written directly to the buffer */
    memcpy((uint8_t *)(rpc_buffer->buffer) + status.rpc_offset_in_buffer, bootloader_chunk->data, bootloader_chunk->data_len);
    status.rpc_offset_in_buffer += bootloader_chunk->data_len;

    return MODEM_RET_SUCCESS;
}


/* Function to write incoming image/firmware data to memory
 * Assumes all data in the same firmware chunk are contigous */
modem_err_t modem_write_firmware_chunk(modem_memory_chunk_t * firmware_chunk){
    modem_err_t err;

    /* Check if the current state allows programming firmware */
    if (status.modem_state != MODEM_STATE_READY_FOR_IPC_COMMANDS){
        return MODEM_RET_INVALID_OPERATION;
    }

    /* Dissallow 0 as address */
    if (firmware_chunk->target_address == 0){
        LOG_DBG("Invalid argument in write_firmware_chunk: target address is zero.\r\n");
        return MODEM_RET_INVALID_ARGUMENT;
    }

    /* Set the new target address if the RPC buffer is empty */
    if (status.rpc_offset_in_buffer == 0){
        status.rpc_data_target_address = firmware_chunk->target_address;
    }

    /* If the target address is not aligned with prev chunk. Submit what is already written in the RPC buffer
     * and update the target address */
    bool address_aligned_with_prev_chunk = ((status.rpc_data_target_address + status.rpc_offset_in_buffer) == firmware_chunk->target_address);
    if (!address_aligned_with_prev_chunk && status.rpc_offset_in_buffer != 0){
        LOG_DBG("Firmware data address is unaligned. Commit data to start new data block\n\r");
        modem_rpc_program_write_metadata(status.rpc_data_target_address, status.rpc_offset_in_buffer);
        err = modem_ipc_trigger_and_check_response(MODEM_RPC_RESP_PROGRAM_RANGE);

        /* Reset offset and assign new target address for RPC buffer data */
        status.rpc_data_target_address = firmware_chunk->target_address;
        status.rpc_offset_in_buffer = 0;

        if (err != MODEM_RET_SUCCESS){
            set_modem_state_bad();
            return err;
        }
    }

    /* Start loop for writing the firmware chunk data */
    uint32_t bytes_written = 0;
    while  (bytes_written < firmware_chunk->data_len){
        /* Write as much as possible to the buffer */
        uint32_t bytes_to_write = MIN(firmware_chunk->data_len - bytes_written, rpc_buffer_payload_size - status.rpc_offset_in_buffer);
        memcpy((uint8_t *)(&(rpc_buffer->program.data)) + status.rpc_offset_in_buffer, firmware_chunk->data + bytes_written, bytes_to_write);

        /* Update offset variables */
        bytes_written += bytes_to_write;
        status.rpc_offset_in_buffer += bytes_to_write;

        /* Submit buffer if full */
        if (status.rpc_offset_in_buffer >= rpc_buffer_payload_size){
            modem_rpc_program_write_metadata(status.rpc_data_target_address, status.rpc_offset_in_buffer);
            err = modem_ipc_trigger_and_check_response(MODEM_RPC_RESP_PROGRAM_RANGE);

            /* Reset offset and assign new target address for RPC buffer data */
            status.rpc_data_target_address += status.rpc_offset_in_buffer;
            status.rpc_offset_in_buffer = 0;

            if (err != MODEM_RET_SUCCESS){
                set_modem_state_bad();
                return err;
            }
        }
    }

    return MODEM_RET_SUCCESS;
}


modem_err_t modem_start_transfer()
{
    /* Check current state */
    if (status.modem_state != MODEM_STATE_WAITING_FOR_BOOTLOADER &&
        status.modem_state != MODEM_STATE_READY_FOR_IPC_COMMANDS){
        return MODEM_RET_INVALID_OPERATION;
    }

    status.rpc_offset_in_buffer = 0;
    return MODEM_RET_SUCCESS;
}


modem_err_t modem_end_transfer()
{
    /* Check current state */
    if (status.modem_state != MODEM_STATE_WAITING_FOR_BOOTLOADER &&
        status.modem_state != MODEM_STATE_READY_FOR_IPC_COMMANDS){
        return MODEM_RET_INVALID_OPERATION;
    }

    /* Skip if no data in buffer */
    if (status.rpc_offset_in_buffer == 0)
    {
        status.modem_state = MODEM_STATE_READY_FOR_IPC_COMMANDS;
        return MODEM_RET_SUCCESS;
    }

    modem_err_t err;
    /* Firmware upload */
    if (status.modem_state == MODEM_STATE_READY_FOR_IPC_COMMANDS){
        /* Firmware upload requires meta information to be written to RPC fields */
        modem_rpc_program_write_metadata(status.rpc_data_target_address, status.rpc_offset_in_buffer);
        err = modem_ipc_trigger_and_check_response(MODEM_RPC_RESP_PROGRAM_RANGE);
    }
    /* Bootloader upload*/
    else{
        err = modem_ipc_trigger_and_check_response(MODEM_RPC_RESP_NONE);
    }

    status.rpc_offset_in_buffer = 0;

    if (err != MODEM_RET_SUCCESS){
        set_modem_state_bad();
        return err;
    }

    /* The resulting state is the same for successful bootloader and firmware upload */
    status.modem_state = MODEM_STATE_READY_FOR_IPC_COMMANDS;

    return MODEM_RET_SUCCESS;
}


/* Function for requesting a digest/hash of a memory range from the modem */
modem_err_t modem_get_memory_hash(uint32_t start_address, uint32_t end_address, modem_digest_buffer_t * digest_buffer){
    /* Check the current state*/
    if (status.modem_state != MODEM_STATE_READY_FOR_IPC_COMMANDS){
        return MODEM_RET_INVALID_OPERATION;
    }

    modem_ipc_clear_events();

    /* Write command indication */
    rpc_buffer->digest.id = MODEM_RPC_CMD_DIGEST_RANGE;

    /* Write a list of memory segments that we want to verify into the ipc_rpc data buffer.
     * The max span/length of each segment to verify is limited by rpc_buffer_payload_size */
    uint32_t segment_counter = 0;
    uint32_t address = start_address;
    uint32_t length = MIN((uint32_t)(end_address - start_address + 1), MODEM_RPC_MAX_DIGEST_RANGE_BYTES);
    while(address < end_address){
        rpc_buffer->digest.ranges[segment_counter].start = address;
        rpc_buffer->digest.ranges[segment_counter].bytes = length;

        /* Update iteration variables */
        address += length;
        length = MIN((uint32_t)(end_address - address + 1), MODEM_RPC_MAX_DIGEST_RANGE_BYTES);
        ++segment_counter;
    }

    /* Check if there is anything to verify */
    if (segment_counter == 0){
        return MODEM_RET_INVALID_ARGUMENT;
    }

    /* Write the number of segments to verify to rpc buffer */
    rpc_buffer->digest.no_ranges = segment_counter;

    /* Intiate verification process */
    modem_err_t err = modem_ipc_trigger_and_check_response(MODEM_RPC_RESP_DIGEST_RANGE);
    if (err != MODEM_RET_SUCCESS){
        set_modem_state_bad();
        return err;
    }

    /* Put the digest response in the response */
    memcpy(digest_buffer->data, (uint8_t *)(rpc_buffer->response.payload), MODEM_DIGEST_BUFFER_LEN);

    return MODEM_RET_SUCCESS;
}


modem_err_t modem_get_uuid(modem_uuid_t * modem_uuid){
    /* Check the current state*/
    if (status.modem_state != MODEM_STATE_READY_FOR_IPC_COMMANDS){
        return MODEM_RET_INVALID_OPERATION;
    }

    rpc_buffer->cmd.id = MODEM_RPC_CMD_READ_UUID;
    modem_err_t err = modem_ipc_trigger_and_check_response(MODEM_RPC_RESP_READ_UUID);
    if (err != MODEM_RET_SUCCESS){
        set_modem_state_bad();
        return err;
    }

    memcpy(modem_uuid->data, (uint8_t *)(rpc_buffer->response.payload), MODEM_UUID_BUFFER_LEN);
    return MODEM_RET_SUCCESS;
}

