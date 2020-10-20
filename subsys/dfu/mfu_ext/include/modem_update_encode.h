/* Generated with cddl_gen.py (https://github.com/oyvindronningstad/cddl_gen)
 */

#ifndef MODEM_UPDATE_ENCODE_H__
#define MODEM_UPDATE_ENCODE_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "cbor_encode.h"
#include "modem_update_types.h"



bool cbor_encode_Wrapper(
		uint8_t * p_payload, size_t payload_len,
		const COSE_Sign1_Manifest_t * p_input,
		size_t *p_payload_len_out);


bool cbor_encode_Sig_structure1(
		uint8_t * p_payload, size_t payload_len,
		const Sig_structure1_t * p_input,
		size_t *p_payload_len_out);


bool cbor_encode_Segments(
		uint8_t * p_payload, size_t payload_len,
		const Segments_t * p_input,
		size_t *p_payload_len_out);


#endif // MODEM_UPDATE_ENCODE_H__
