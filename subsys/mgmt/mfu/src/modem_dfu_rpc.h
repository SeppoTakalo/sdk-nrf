#ifndef __MODEM_DFU_RPC_H__
#define __MODEM_DFU_RPC_H__

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


/* This library API can be used to do a full upgrade of the nrf91 modem firmware.
 * As of now, Feb 2020, there are four files of interest included in the modem firmware zip folder:
 *     #1 72B3D7C.ipc_dfu.signed_<version_number>.ihex
 *        This is the modem bootloader file, which is the first hex file you must give to the modem. The preceeding numbers 
 *        "72B3D7C" in the filename equivalents to the hex value of the root digest hash value the modem responds with after
 *        being put in DFU mode. The bootloader hex file is assumed contigous and less than one page in size (0x2000 byte).
 *        Note that programming the bootloader is slightly different from the other hex files, as the modem doesn't need an
 *        address describing where to put the data.
 *
 *     #2 firmware.update.image.segments.0.hex
 *        This file contains meta-info about the main firmware file, and is significantly smaller than the second segment.
 *        It acts as a key the modem uses to verify the chunks of firmware data in file #3. It must be programmed after
 *        the bootloader has been accepted.
 *
 *
 *
 *
 */


hash = blabal
signature = blabal

[(0x234082, 0x7000), (0x200, 0x2304820)]

cbor_map_BL(
	target_addr: 0x8320482304)
	len: 100
cbor_map_FW0(
	target_addr: 0x20000
cbor_map_FW1(
	target_addr:

	data_BL: 0x...)
	data_FW0: 0x...)
	data_FW1: 0x...
	target_addr: 0x800030
 BL
 FW0
 FW1
 FW2

 /*
 *
 *     #3 firmware.update.image.segments.1.hex
 *        The main firmware file. This hex file has multiple memory regions (contigous regions).
 *
 *     #4 firmware.update.image.digest.txt
 *        The digest file is a plain text file that describes a set of memory ranges in the modem, and the expected hash value
 *        of the content of these memory ranges. This is used post-upgrade to verify the modem memory contents, and is mostly
 *        useful in the case where a re-upload of the modem is possible without the use of the modem.
 *        
 *
 * About data representation:
 *        This library requires that any firmware/hex files are converted to a binary representation. When writing data to the
 *        modem one must supply:
 *            - a byte array of contigous data. 
 *            - a target address
 *            - the length of the array
 *        These values are passed using the struct 'modem_memory_chunk_t'.
 *
 *        The address describes where to put the first byte of the byte array (in the modem memory), and is found when parsing
 *        the hex file. Contigous data means that the bytes in the array belongs as a single uninterrupted sequence, i.e. a
 *        block of data in memory. This implies that if the hex files describes multiple regions of contigous data it must be
 *        fragmented to contigous blocks before programming. This is the case for firmware segment.1 (file #3). Moreover, some
 *        of the contigous data blocks are too large to be held in memory and needs to be broken down into a set of shorter byte
 *        arrays.
 *
 *        When programming firmware/bootloader, use repeated calls to the write function 'modem_write_firmware_chunk' or
 *        'modem_write_bootloader_chunk'.
 *
 *        Write process pseudocode for a hex file split into binary contigous blocks:
 *
 *            modem_start_transfer()
 *            modem_memory_chunk_t memory_chunk
 *            uint8_t buffer[200]
 *            memory_chunk.data = buffer
 *            for block in contigous_blocks
 *                bytes_read = 0
 *                while bytes_read < block.length 
 *                    n_bytes = read_block(from:  block, to: buffer, max_bytes: 200)
 *                    memory_chunk.target_address   = block.start_address + bytes_read
 *                    memory_chunk.data_len         = n_bytes
 *                    modem_write_firmware_chunk( &memory_chunk)
 *                    bytes_read  += n_bytes
 *            modem_end_transfer()            
 *        
 * 
 * How to perform a full modem firmware upgrade using this library in steps:
 *     1) Run the initialize function
 *        This function will configure the RAM and IPC to non-secure and set up the required IPC channels. Then the address of
 *        an RPC descriptor is written to GPMEM[0]. This descriptor gives the modem information about the API version to use,
 *        and the length and address of the communication buffer. The communication buffer is set to be a minimum of 1 page (2kB)
 *        plus the maximum overhead of the RPC protocol (16B / 4 x uint32).
 * 
 *        The init function takes a pointer to a digest_buffer_t struct. If successful, the root digest hash modem response is
 *        put into the buffer.
 *
 *     2) (Optional): Use the root digest hash that you obtained from the init function to verify you have the correct bootloader
 *        by comparing it to the hex filename (file #1).
 *
 *     3) Program the files in order:
 *            Bootloader  (file #1)
 *            segment0     (file #2)
 *            segment1    (file #3)
 *        
 *        (See note on data representation)
 *        For each file do:
 *            - Invoke the 'modem_start_transfer' function before writing data to the modem. In practice, this function does not
 *              communicate with the modem, it only resets variables used to load data into the RPC buffer.
 *            - Write the data by using either 'modem_write_bootloader_chunk' or 'modem_write_firmware_chunk'. These functions
 *              takes a pointer to a 'modem_memory_chunk_t' struct that holds a piece of contigous data and a target address.
 *              Note that the 'target_address' field of the struct is ignored when writing the bootloader.
 *            - Invoke modem_end_transfer to finalize the transfer. If this function returns MODEM_SUCCESS, the programming was
 *              successful.
 *        
 *     4) (Optional): Use the digest text file (file #4) to verify that the modem firmware is correct
 *        Use the 'modem_get_memory_hash' to get a 256-bit hash of a memory region. Compare the result with the number in the
 *        text file. Remember to convert the text file number to binary before comparing.
 *        
 *  About error handling:
 *        The library uses an internal state machine to check whether an action is permitted
 *
 *        +-------+
 *        | Start |
 *        +--+----+
 *           | Init IPC
 *           | and RAM
 *           v                       Error
 *        +--+------------+  Error   +---+
 *        | Modem         +------+   |   |
 *        | Uninitialized |      v   |   v
 *        +--+------------+    +-+---+---+-+
 *           |                 | Modem bad |
 *           +<----------------+ state     |
 *           |  Initialize     +--------+--+
 *           v                          ^
 *        +--+----------+               |
 *        | Waiting for |               |
 *        | bootloader  +-------------->+
 *        +--+----------+  Error        |
 *           |  Program                 |
 *           |  bootloader              |
 *           v                          |
 *        +--+------------+             |
 *        | Ready for RPC +-------------+
 *        | commands      |  Error
 *        +-+---+---+---+-+
 *          |   ^   |   ^
 *          |   |   |   |
 *          +---+   +---+
 *         Program  Verify
 *        
 *
 *        MODEM_STATE_UNINITIALIZED
 *          The program is in an uninitialized state before calling the init function 'modem_dfu_rpc_init'. If the init function is
 *          successful, the state continues to MODEM_STATE_WAITING_FOR_BOOTLOADER.
 *
 *          If the the init function returns an error, we enter MODEM_STATE_BAD. This occurs if the modem does not signal the IPC
 *          within a timelimit after being put in DFU mode. Usually, this has only been the case if the shared RAM region or IPC has
 *          been configured with the wrong settings/permissions and should not happen.
 *
 *        MODEM_STATE_WAITING_FOR_BOOTLOADER
 *          After putting the modem in DFU mode, it expects to recieve a bootloader. Other actions such as program and verify will fail
 *          before the bootloader is programmed. If the programming is successful the modem is ready for RPC communication, i.e. we enter
 *          the MODEM_STATE_READY_FOR_IPC_COMMANDS state.
 *
 *          If corrupted data is input instead of a valid bootloader we go to MODEM_STATE_BAD. This can be either because the modem
 *          signaled a fault, or as a result of a response timeout.
 *          
 *        MODEM_STATE_READY_FOR_IPC_COMMANDS
 *          In this state, we can send requests to program a region of the modem flash, or ask for a hash of a memory range . However,
 *          this state has a hidden state, as you first need to program segment.0 (file #2) before you can program the rest of the firmware.
 *
 *          If the modem signals a fault or error, or fails to respons, we enter MODEM_STATE_BAD.
 *
 *        MODEM_STATE_BAD
 *          Some operation that was attempted with the modem failed, and usually the reason is unknown. The modem performs validation of the
 *          files we want to program, and can f.ex. signal an error because of firmware downgrade protection (not all versions have this).
 *          To get out of this state, re-initialize the modem using the init function. This will reset all your progress and you will have to
 *          go through all the steps again. Note that in some cases a when there is an unidentified problem, it can't be fixed by running 
 *          the init function such that a board reset might be necessary.
 *        
 *        You can also use the following function to get information about the modem state:
 *            - modem_state_t modem_get_state(void);
 *        
 *        Also, check the return value of the function calls to see if it was successful.
 *
 *        If the modem responds with IPC_DFU_RESP_UNKNOWN_CMD (0x5A000001ul), the modem could not interpret the RPC data and a fault
 *        indication flag is set. The modem can indicate a fault both through the RPC response field and by writing a value to GPMEM[1].
 *        If the modem responds with IPC_DFU_RESP_CMD_ERROR (0x5A000002ul), the modem have rejected the command. A few possible reasons for
 *        this are:
 *            - data block target address range is invalid (valid ranges are 0x6000...0xFFFF and 0x50000...0x27FFFF)
 *            - data block size is bigger than the shared memory area size
 *            - data block size is bigger than FLASH size 0x280000
 *            - data block target address is not aligned to FLASH page (0x2000 bytes)
 *            - metadata is invalid
 *            - data block integrity check failed
 *            - flash target block erase failed
 *            - flash target block write failed
 * 
 *        By design, the response of the modem is limited to make it harder for an attacker to get information from the device. Unfortunately,
 *        this means extra harm for the user. The only option for recovering the modem state provided in this API is to restart the DFU
 *        from scratch. 
 * 
 *   (Optional) Remove dependency on zephyr by using SysTick for timing:
 *      By default, the library uses zephyr's 'k_sleep', 'k_get_uptime' and 'k_uptime_delta' for timing, mainly for detecting when the
 *      communication with the modem has reached a timeout. If you want to drop zephyr as a dependency the Cortex-M33 SysTick timer can be
 *      used instead. If used, the API assumes it has exclusive access to the timer for the duration of the DFU operation, but it will not
 *      define an interrupt handler.
 *
 *      To enable SysTick usage define MODEM_DFU_RPC_USE_SYSTICK as a compile option. For example, if you are using CMake, append
 *      add_definitions(-DMODEM_DFU_RPC_USE_SYSTICK).
 *      
 *      If the TENMS calibration value in the SysTick->CALIB is unset (has value 0), a TENMS value is calculated
 *      using SystemCoreClock (CLKSOURCE in SysTick->CTRL is not checked). Keep in mind that there exist two SysTick timers, one for
 *      secure and one for non-secure (timer is banked between security states).
 *
 */

#include <stdint.h>

/* Function return codes */
typedef enum {
    MODEM_RET_SUCCESS                   =  0,   /* SUCCESS */
    MODEM_RET_IPC_FAULT_EVENT           = -1,   /* The modem signaled a fault on the fault IPC channel (IPCEVENT_FAULT_RECEIVE_CHANNEL) */
    MODEM_RET_RPC_UNEXPECTED_RESPONSE   = -2,   /* The modem response code in the RPC buffer (rpc_buffer->response.id) did not match the expected value */
    MODEM_RET_RPC_COMMAND_FAILED        = -3,   /* The modem replied with MODEM_RPC_RESP_CMD_ERROR to an RPC command */
    MODEM_RET_RPC_COMMAND_FAULT         = -4,   /* The modem replied with MODEM_RPC_RESP_UNKNOWN_CMD to an RPC command*/
    MODEM_RET_RPC_TIMEOUT               = -5,   /* Timout while waiting for modem to respond on IPC channel */
    MODEM_RET_INVALID_ARGUMENT          = -6,   /* An invalid argument was passed to the function */
    MODEM_RET_INVALID_OPERATION         = -7    /* The function/operation is not allowed with the current modem state */
} modem_err_t; 

/* Modem states */
typedef enum {
    MODEM_STATE_UNINITIALIZED           = 1,
    MODEM_STATE_WAITING_FOR_BOOTLOADER  = 2,
    MODEM_STATE_READY_FOR_IPC_COMMANDS  = 3,
    MODEM_STATE_BAD                     = 4
} modem_state_t;


/* Struct type for passing firmware data.
 * One piece of contiguous firmware is split into smaller modem_memory_chunk_t chunks. */
typedef struct {
    /* Destination address for the data (read by the modem)
     * Not used with bootloader firmware */
    uint32_t target_address;

    /* Chunk data and length (num bytes) */
    uint32_t data_len;
    uint8_t * data;
} modem_memory_chunk_t;


#define MODEM_DIGEST_BUFFER_LEN   32
#define MODEM_UUID_BUFFER_LEN     36

/* Struct type for storing 256-bit digest/hash replies */
typedef struct {
    uint8_t data[MODEM_DIGEST_BUFFER_LEN];
} modem_digest_buffer_t;

/* Struct for storing modem UUID response (36B) */
typedef struct {
    uint8_t data[MODEM_UUID_BUFFER_LEN];
} modem_uuid_t;


/* The init function takes an array and the length of the array. The array is used as shared RAM to communicate
 * with the modem. The RPC payload must be modem page aligned, which means the smallest possible buffer is 1 page + RPC overhead data.
 * In general, use array lenghts of the form:     MODEM_RPC_OVERHEAD_SIZE + n * MODEM_RPC_MODEM_PAGE_SIZE, for n[1 .. 8] 
 * A larger buffer does not necessarily mean better performance */
#define MODEM_RPC_PAGE_SIZE                     0x2000
#define MODEM_RPC_OVERHEAD_SIZE                 0xC
#define MODEM_RPC_BUFFER_MIN_SIZE               (MODEM_RPC_OVERHEAD_SIZE + MODEM_RPC_PAGE_SIZE * 1)
#define MODEM_RPC_BUFFER_MAX_SIZE               (MODEM_RPC_OVERHEAD_SIZE + MODEM_RPC_PAGE_SIZE * 8)

/* Init modem in DFU/RPC mode.
 * Call once before DFU operation. If the modem goes to a bad state, this can be called again to re-initialize.
 * The root key digest response of the modem is put in the digest_buffer argument
 * If success, modem will be in MODEM_STATE_WAITING_FOR_BOOTLOADER */
modem_err_t modem_dfu_rpc_init(modem_digest_buffer_t * digest_buffer, uint8_t* modem_rpc_buffer, uint32_t modem_rpc_buffer_length);


/* Functions for writing a chunk of data to the modem.
 * Use modem_start_transfer and modem_end_transfer at the start and end of a firmware upload. 
 * See notes 'About data representation' above for a pseudocode example */
modem_err_t modem_write_bootloader_chunk(modem_memory_chunk_t * bootloader_chunk);
modem_err_t modem_write_firmware_chunk(modem_memory_chunk_t * firmware_chunk);
modem_err_t modem_start_transfer(void);
modem_err_t modem_end_transfer(void);

/* Requires modem state MODEM_STATE_READY_FOR_IPC_COMMANDS */
modem_err_t modem_get_memory_hash(uint32_t start_address, uint32_t end_address, modem_digest_buffer_t * digest_buffer);
modem_err_t modem_get_uuid(modem_uuid_t * modem_uuid);

/* Functions for reading modem state.
 * If modem is in MODEM_STATE_BAD, one can check if an fault or error
 * was indicated from the modem */
modem_state_t modem_get_state(void);

#endif /*__MODEM_DFU_RPC_H__*/
