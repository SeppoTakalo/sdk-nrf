/* Generated with cddl_gen.py (https://github.com/oyvindronningstad/cddl_gen)
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "cbor_decode.h"
#include "modem_update_decode.h"


static bool decode_Segment(
		cbor_state_t *p_state, Segment_t *p_result)
{
	cbor_print(__func__ "\n");

	bool result = (((((uintx32_decode(p_state, (&(*p_result)._Segment_target_addr))))
	&& ((uintx32_decode(p_state, (&(*p_result)._Segment_len)))))));

	if (!result)
		cbor_trace();

	return result;
}

static bool decode_header_map(
		cbor_state_t *p_state, void *p_result)
{
	cbor_print(__func__ "\n");
	bool int_res;

	bool result = (((map_start_decode(p_state) && (int_res = ((((uintx32_expect(p_state, (1))))
	&& (intx32_expect(p_state, (-37))))), ((map_end_decode(p_state)) && int_res)))));

	if (!result)
		cbor_trace();

	return result;
}

static bool decode_Manifest(
		cbor_state_t *p_state, Manifest_t *p_result)
{
	cbor_print(__func__ "\n");
	bool int_res;

	bool result = (((list_start_decode(p_state) && (int_res = (((uintx32_decode(p_state, (&(*p_result)._Manifest_version))))
	&& ((uintx32_decode(p_state, (&(*p_result)._Manifest_compat))))
	&& ((bstrx_decode(p_state, (&(*p_result)._Manifest_blob_hash)))
	&& ((*p_result)._Manifest_blob_hash.len >= 32)
	&& ((*p_result)._Manifest_blob_hash.len <= 32))
	&& ((bstrx_decode(p_state, (&(*p_result)._Manifest_segments))))), ((list_end_decode(p_state)) && int_res)))));

	if (!result)
		cbor_trace();

	return result;
}

static bool decode_COSE_Sign1_Manifest(
		cbor_state_t *p_state, COSE_Sign1_Manifest_t *p_result)
{
	cbor_print(__func__ "\n");
	bool int_res;

	bool result = (((list_start_decode(p_state) && (int_res = ((((int_res = (bstrx_cbor_start_decode(p_state, &(*p_result)._COSE_Sign1_Manifest_protected)
	&& ((decode_header_map(p_state, (&(*p_result)._COSE_Sign1_Manifest_protected_cbor)))))), bstrx_cbor_end_decode(p_state), int_res))
	&& ((map_start_decode(p_state) && map_end_decode(p_state)))
	&& (((int_res = (bstrx_cbor_start_decode(p_state, &(*p_result)._COSE_Sign1_Manifest_payload)
	&& ((decode_Manifest(p_state, (&(*p_result)._COSE_Sign1_Manifest_payload_cbor)))))), bstrx_cbor_end_decode(p_state), int_res))
	&& ((bstrx_decode(p_state, (&(*p_result)._COSE_Sign1_Manifest_signature)))
	&& ((*p_result)._COSE_Sign1_Manifest_signature.len >= 256)
	&& ((*p_result)._COSE_Sign1_Manifest_signature.len <= 256))), ((list_end_decode(p_state)) && int_res)))));

	if (!result)
		cbor_trace();

	return result;
}

static bool decode_Segments(
		cbor_state_t *p_state, Segments_t *p_result)
{
	cbor_print(__func__ "\n");
	bool int_res;

	bool result = (((list_start_decode(p_state) && (int_res = (multi_decode(1, 64, &(*p_result)._Segments__Segment_count, (void *)decode_Segment, p_state, (&(*p_result)._Segments__Segment), sizeof(Segment_t))), ((list_end_decode(p_state)) && int_res)))));

	if (!result)
		cbor_trace();

	return result;
}

static bool decode_Sig_structure1(
		cbor_state_t *p_state, Sig_structure1_t *p_result)
{
	cbor_print(__func__ "\n");
	cbor_string_type_t tmp_str;
	bool int_res;

	bool result = (((list_start_decode(p_state) && (int_res = (((tstrx_expect(p_state, ((tmp_str.value = "Signature1", tmp_str.len = 10, &tmp_str)))))
	&& (((int_res = (bstrx_cbor_start_decode(p_state, &(*p_result)._Sig_structure1_body_protected)
	&& ((decode_header_map(p_state, (&(*p_result)._Sig_structure1_body_protected_cbor)))))), bstrx_cbor_end_decode(p_state), int_res))
	&& ((bstrx_expect(p_state, ((tmp_str.value = "", tmp_str.len = 0, &tmp_str)))))
	&& ((bstrx_decode(p_state, (&(*p_result)._Sig_structure1_payload))))), ((list_end_decode(p_state)) && int_res)))));

	if (!result)
		cbor_trace();

	return result;
}

static bool decode_Wrapper(
		cbor_state_t *p_state, COSE_Sign1_Manifest_t *p_result)
{
	cbor_print(__func__ "\n");

	bool result = ((tag_expect(p_state, 18)
	&& (decode_COSE_Sign1_Manifest(p_state, (&(*p_result))))));

	if (!result)
		cbor_trace();

	return result;
}



bool cbor_decode_Wrapper(
		const uint8_t *p_payload, size_t payload_len,
		COSE_Sign1_Manifest_t *p_result,
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

	bool result = decode_Wrapper(&state, p_result);

	if (result && (p_payload_len_out != NULL)) {
		*p_payload_len_out = MIN(payload_len,
				(size_t)state.p_payload - (size_t)p_payload);
	}
	return result;
}


bool cbor_decode_Sig_structure1(
		const uint8_t *p_payload, size_t payload_len,
		Sig_structure1_t *p_result,
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

	bool result = decode_Sig_structure1(&state, p_result);

	if (result && (p_payload_len_out != NULL)) {
		*p_payload_len_out = MIN(payload_len,
				(size_t)state.p_payload - (size_t)p_payload);
	}
	return result;
}


bool cbor_decode_Segments(
		const uint8_t *p_payload, size_t payload_len,
		Segments_t *p_result,
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

	bool result = decode_Segments(&state, p_result);

	if (result && (p_payload_len_out != NULL)) {
		*p_payload_len_out = MIN(payload_len,
				(size_t)state.p_payload - (size_t)p_payload);
	}
	return result;
}
