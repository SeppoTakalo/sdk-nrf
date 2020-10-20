/* Generated with cddl_gen.py (https://github.com/oyvindronningstad/cddl_gen)
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "cbor_encode.h"
#include "modem_update_encode.h"


static bool encode_Segment(
		cbor_state_t *p_state, const Segment_t * p_input)
{
	cbor_print("encode_Segment\n");

	bool result = (((((uintx32_encode(p_state, (&(*p_input)._Segment_target_addr))))
	&& ((uintx32_encode(p_state, (&(*p_input)._Segment_len)))))));

	if (!result)
	{
		cbor_trace();
	}

	return result;
}

static bool encode_header_map(
		cbor_state_t *p_state, const void * p_input)
{
	cbor_print("encode_header_map\n");
	uint32_t tmp_value;
	bool int_res;

	bool result = (((map_start_encode(p_state, 1) && (int_res = ((((uintx32_encode(p_state, ((tmp_value=1, &tmp_value)))))
	&& (intx32_encode(p_state, ((tmp_value=-7, &tmp_value)))))), ((map_end_encode(p_state, 1)) && int_res)))));

	if (!result)
	{
		cbor_trace();
	}

	return result;
}

static bool encode_Manifest(
		cbor_state_t *p_state, const Manifest_t * p_input)
{
	cbor_print("encode_Manifest\n");
	bool int_res;

	bool result = (((list_start_encode(p_state, 4) && (int_res = (((uintx32_encode(p_state, (&(*p_input)._Manifest_version))))
	&& ((uintx32_encode(p_state, (&(*p_input)._Manifest_compat))))
	&& ((bstrx_encode(p_state, (&(*p_input)._Manifest_blob_hash))))
	&& ((bstrx_encode(p_state, (&(*p_input)._Manifest_segments))))), ((list_end_encode(p_state, 4)) && int_res)))));

	if (!result)
	{
		cbor_trace();
	}

	return result;
}

static bool encode_COSE_Sign1_Manifest(
		cbor_state_t *p_state, const COSE_Sign1_Manifest_t * p_input)
{
	cbor_print("encode_COSE_Sign1_Manifest\n");
	bool int_res;

	bool result = (((list_start_encode(p_state, 4) && (int_res = ((((*p_input)._COSE_Sign1_Manifest_protected.value ? ((bstrx_encode(p_state, (&(*p_input)._COSE_Sign1_Manifest_protected)))) : (((int_res = (bstrx_cbor_start_encode(p_state, &(*p_input)._COSE_Sign1_Manifest_protected)
	&& ((encode_header_map(p_state, (&(*p_input)._COSE_Sign1_Manifest_protected_cbor)))))), bstrx_cbor_end_encode(p_state), int_res))))
	&& ((map_start_encode(p_state, 0) && map_end_encode(p_state, 0)))
	&& (((*p_input)._COSE_Sign1_Manifest_payload.value ? ((bstrx_encode(p_state, (&(*p_input)._COSE_Sign1_Manifest_payload)))) : (((int_res = (bstrx_cbor_start_encode(p_state, &(*p_input)._COSE_Sign1_Manifest_payload)
	&& ((encode_Manifest(p_state, (&(*p_input)._COSE_Sign1_Manifest_payload_cbor)))))), bstrx_cbor_end_encode(p_state), int_res))))
	&& ((bstrx_encode(p_state, (&(*p_input)._COSE_Sign1_Manifest_signature))))), ((list_end_encode(p_state, 4)) && int_res)))));

	if (!result)
	{
		cbor_trace();
	}

	return result;
}

static bool encode_Segments(
		cbor_state_t *p_state, const Segments_t * p_input)
{
	cbor_print("encode_Segments\n");
	bool int_res;

	bool result = (((list_start_encode(p_state, 6) && (int_res = (multi_encode(1, 3, &(*p_input)._Segments__Segment_count, (void*)encode_Segment, p_state, (&(*p_input)._Segments__Segment), sizeof(Segment_t))), ((list_end_encode(p_state, 6)) && int_res)))));

	if (!result)
	{
		cbor_trace();
	}

	return result;
}

static bool encode_Sig_structure1(
		cbor_state_t *p_state, const Sig_structure1_t * p_input)
{
	cbor_print("encode_Sig_structure1\n");
	cbor_string_type_t tmp_str;
	bool int_res;

	bool result = (((list_start_encode(p_state, 4) && (int_res = (((tstrx_encode(p_state, ((tmp_str.value = "Signature1", tmp_str.len = 10, &tmp_str)))))
	&& (((*p_input)._Sig_structure1_body_protected.value ? ((bstrx_encode(p_state, (&(*p_input)._Sig_structure1_body_protected)))) : (((int_res = (bstrx_cbor_start_encode(p_state, &(*p_input)._Sig_structure1_body_protected)
	&& ((encode_header_map(p_state, (&(*p_input)._Sig_structure1_body_protected_cbor)))))), bstrx_cbor_end_encode(p_state), int_res))))
	&& ((bstrx_encode(p_state, ((tmp_str.value = "", tmp_str.len = 0, &tmp_str)))))
	&& ((bstrx_encode(p_state, (&(*p_input)._Sig_structure1_payload))))), ((list_end_encode(p_state, 4)) && int_res)))));

	if (!result)
	{
		cbor_trace();
	}

	return result;
}

static bool encode_Wrapper(
		cbor_state_t *p_state, const COSE_Sign1_Manifest_t * p_input)
{
	cbor_print("encode_Wrapper\n");

	bool result = ((tag_encode(p_state, 18)
	&& (encode_COSE_Sign1_Manifest(p_state, (&(*p_input))))));

	if (!result)
	{
		cbor_trace();
	}

	return result;
}



bool cbor_encode_Wrapper(
		uint8_t * p_payload, size_t payload_len,
		const COSE_Sign1_Manifest_t * p_input,
		size_t *p_payload_len_out)
{
	cbor_state_t state = {
		.p_payload = p_payload,
		.p_payload_end = p_payload + payload_len,
		.elem_count = 1
	};

	cbor_state_t state_backups[4];

	cbor_state_backups_t backups = {
		.p_backup_list = state_backups,
		.current_backup = 0,
		.num_backups = 4,
	};

	state.p_backups = &backups;

	bool result = encode_Wrapper(&state, p_input);

	if (result && (p_payload_len_out != NULL)) {
		*p_payload_len_out = MIN(payload_len,
				(size_t)state.p_payload - (size_t)p_payload);
	}
	return result;
}


bool cbor_encode_Sig_structure1(
		uint8_t * p_payload, size_t payload_len,
		const Sig_structure1_t * p_input,
		size_t *p_payload_len_out)
{
	cbor_state_t state = {
		.p_payload = p_payload,
		.p_payload_end = p_payload + payload_len,
		.elem_count = 1
	};

	cbor_state_t state_backups[4];

	cbor_state_backups_t backups = {
		.p_backup_list = state_backups,
		.current_backup = 0,
		.num_backups = 4,
	};

	state.p_backups = &backups;

	bool result = encode_Sig_structure1(&state, p_input);

	if (result && (p_payload_len_out != NULL)) {
		*p_payload_len_out = MIN(payload_len,
				(size_t)state.p_payload - (size_t)p_payload);
	}
	return result;
}


bool cbor_encode_Segments(
		uint8_t * p_payload, size_t payload_len,
		const Segments_t * p_input,
		size_t *p_payload_len_out)
{
	cbor_state_t state = {
		.p_payload = p_payload,
		.p_payload_end = p_payload + payload_len,
		.elem_count = 1
	};

	cbor_state_t state_backups[2];

	cbor_state_backups_t backups = {
		.p_backup_list = state_backups,
		.current_backup = 0,
		.num_backups = 2,
	};

	state.p_backups = &backups;

	bool result = encode_Segments(&state, p_input);

	if (result && (p_payload_len_out != NULL)) {
		*p_payload_len_out = MIN(payload_len,
				(size_t)state.p_payload - (size_t)p_payload);
	}
	return result;
}
