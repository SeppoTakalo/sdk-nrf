/* Generated with cddl_gen.py (https://github.com/oyvindronningstad/cddl_gen)
 */

#ifndef MODEM_UPDATE_DECODE_H__
#define MODEM_UPDATE_DECODE_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "cbor_decode.h"
#include "modem_update_types.h"



bool cbor_decode_Wrapper(
		const uint8_t * p_payload, size_t payload_len,
		COSE_Sign1_Manifest_t * p_result,
		size_t *p_payload_len_out);


bool cbor_decode_Sig_structure1(
		const uint8_t * p_payload, size_t payload_len,
		Sig_structure1_t * p_result,
		size_t *p_payload_len_out);


bool cbor_decode_Segments(
		const uint8_t * p_payload, size_t payload_len,
		Segments_t * p_result,
		size_t *p_payload_len_out);


#endif // MODEM_UPDATE_DECODE_H__
