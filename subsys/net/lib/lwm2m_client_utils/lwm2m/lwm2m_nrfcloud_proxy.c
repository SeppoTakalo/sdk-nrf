/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#define LOG_MODULE_NAME nrfcloud_lwm2m_proxy
#define LOG_LEVEL CONFIG_LWM2M_LOG_LEVEL

#include <logging/log.h>
LOG_MODULE_REGISTER(LOG_MODULE_NAME);

#include <stdint.h>
#include <init.h>

#include "lwm2m_object.h"
#include "lwm2m_engine.h"
#include "lwm2m_resource_ids.h"

#define PROXY_OBJ_ID 666
#define ID_METHOD 0
#define ID_PATH 1
#define ID_HEADERS 2
#define ID_PAYLOAD 3
#define ID_RESPONSE_CODE 4
#define ID_RESPONSE_TYPE 5
#define ID_RESPONSE_PAYLOAD 6

#define EXAMPLE_MIME_TYPE "application/vnd.oma.lwm2m+json"

#define VERSION_MAJOR 1
#define VERSION_MINOR 0
#define MAX_INSTANCE_COUNT 1
#define MAX_ID ID_RESPONSE_PAYLOAD

static struct lwm2m_engine_obj nrf_proxy;
static struct lwm2m_engine_obj_field fields[] = { OBJ_FIELD_DATA(ID_METHOD, R, U8),
						  OBJ_FIELD_DATA(ID_PATH, R, STRING),
						  OBJ_FIELD_DATA(ID_HEADERS, R, STRING),
						  OBJ_FIELD_DATA(ID_PAYLOAD, R, OPAQUE),
						  OBJ_FIELD_DATA(ID_RESPONSE_CODE, W, U16),
						  OBJ_FIELD_DATA(ID_RESPONSE_TYPE, W, STRING),
						  OBJ_FIELD_DATA(ID_RESPONSE_PAYLOAD, W, OPAQUE) };
static struct lwm2m_engine_obj_inst inst;
static struct lwm2m_engine_res res[MAX_ID + 1];
static struct lwm2m_engine_res_inst res_inst[MAX_ID + 1];

enum query_method {
	GET = 0,
	POST = 1,
	PUT = 2,
};

struct nrfcloud_proxy_query {
	uint8_t method;
	char *path;
	char *headers;
	uint8_t *payload;
	size_t payload_size;
};
static struct nrfcloud_proxy_query query;

struct nrfcloud_proxy_result {
	uint16_t code;
	char type[sizeof(EXAMPLE_MIME_TYPE)];
	uint8_t *payload;
	size_t payload_size;
};
static struct nrfcloud_proxy_result result;

static void *get_path_cb(uint16_t obj_inst_id, uint16_t res_id, uint16_t res_inst_id,
			 size_t *data_len)
{
	ARG_UNUSED(obj_inst_id);
	ARG_UNUSED(res_id);
	ARG_UNUSED(res_inst_id);

	if (!query.path) {
		*data_len = 0;
		return NULL;
	}

	*data_len = strlen(query.path);
	return query.path;
}

static void *get_headers_cb(uint16_t obj_inst_id, uint16_t res_id, uint16_t res_inst_id,
			    size_t *data_len)
{
	ARG_UNUSED(obj_inst_id);
	ARG_UNUSED(res_id);
	ARG_UNUSED(res_inst_id);

	if (!query.headers) {
		*data_len = 0;
		return NULL;
	}

	*data_len = strlen(query.headers);
	return query.headers;
}

static void *get_payload_cb(uint16_t obj_inst_id, uint16_t res_id, uint16_t res_inst_id,
			    size_t *data_len)
{
	ARG_UNUSED(obj_inst_id);
	ARG_UNUSED(res_id);
	ARG_UNUSED(res_inst_id);

	if (!query.payload) {
		*data_len = 0;
		return NULL;
	}

	*data_len = query.payload_size;
	return query.payload;
}

static void *get_resp_payload_cb(uint16_t obj_inst_id, uint16_t res_id, uint16_t res_inst_id,
				 size_t *data_len)
{
	ARG_UNUSED(obj_inst_id);
	ARG_UNUSED(res_id);
	ARG_UNUSED(res_inst_id);

	if (!result.payload) {
		*data_len = 0;
		return NULL;
	}

	*data_len = result.payload_size;
	return result.payload;
}

static int response_cb(uint16_t obj_inst_id, uint16_t res_id, uint16_t res_inst_id, uint8_t *data,
		       uint16_t data_len, bool last_block, size_t total_size)
{
	ARG_UNUSED(obj_inst_id);
	ARG_UNUSED(res_inst_id);

	LOG_DBG("Got response to /%d/%d/%d", PROXY_OBJ_ID, 0, res_id);

	if (!last_block) {
		return 0;
	}

	/* Get the total size of received payload */
	if (res_id == ID_RESPONSE_PAYLOAD) {
		result.payload_size = total_size;
	}

	/* Check if we have now received all response fields */
	if (result.code == 0 || result.payload_size == 0 || strlen(result.type) == 0) {
		/* No, some fields are still missing */
		LOG_DBG("Pending for more data");
		return 0;
	}

	/* TODO: Now we have all, notify the caller */
	LOG_DBG("Whole response received");
	return 0;
}

int lwm2m_nrfcloud_proxy_qet(char *url)
{
	memset(&query, 0, sizeof(query));
	memset(&result, 0, sizeof(result));
	query.path = url;
	query.method = GET;
	// TODO LWM2M SEND
	LOG_ERR("Send Query to %s", log_strdup(url));
	return 0;
}

static struct lwm2m_engine_obj_inst *nrfcloud_proxy_create(uint16_t obj_inst_id)
{
	int i = 0, j = 0;

	/* We only support one instance, check that only one is created */
	if (inst.obj) {
		LOG_ERR("Can not create instance - "
			"already existing: %u",
			obj_inst_id);
		return NULL;
	}

	if (obj_inst_id >= MAX_INSTANCE_COUNT) {
		LOG_ERR("Can not create instance - no more room: %u", obj_inst_id);
		return NULL;
	}

	(void)memset(res, 0, sizeof(res[0]) * ARRAY_SIZE(res));
	init_res_instance(res_inst, ARRAY_SIZE(res_inst));

	/* initialize instance resource data */
	INIT_OBJ_RES(ID_METHOD, res, i, res_inst, j, 1, false, true, &query.method,
		     sizeof(query.method), NULL, NULL, NULL, NULL, NULL);
	INIT_OBJ_RES_OPT(ID_PATH, res, i, res_inst, j, 1, false, true, get_path_cb, get_path_cb,
			 NULL, NULL, NULL);
	INIT_OBJ_RES_OPT(ID_HEADERS, res, i, res_inst, j, 1, false, true, get_headers_cb,
			 get_headers_cb, NULL, NULL, NULL);
	INIT_OBJ_RES_OPT(ID_PAYLOAD, res, i, res_inst, j, 1, false, true, get_payload_cb,
			 get_payload_cb, NULL, NULL, NULL);
	INIT_OBJ_RES(ID_RESPONSE_CODE, res, i, res_inst, j, 1, false, true, &result.code,
		     sizeof(result.code), NULL, NULL, NULL, response_cb, NULL);
	INIT_OBJ_RES(ID_RESPONSE_TYPE, res, i, res_inst, j, 1, false, true, result.type,
		     sizeof(result.type), NULL, NULL, NULL, response_cb, NULL);
	INIT_OBJ_RES_OPT(ID_RESPONSE_PAYLOAD, res, i, res_inst, j, 1, false, true,
			 get_resp_payload_cb, get_resp_payload_cb, NULL, response_cb, NULL);
	inst.resources = res;
	inst.resource_count = i;
	LOG_DBG("Create nRFCloud Proxy instance: %d", obj_inst_id);
	return &inst;
}

static int nrfcloud_proxy_init(const struct device *dev)
{
	nrf_proxy.obj_id = PROXY_OBJ_ID;
	nrf_proxy.version_major = VERSION_MAJOR;
	nrf_proxy.version_minor = VERSION_MINOR;
	nrf_proxy.is_core = false;
	nrf_proxy.fields = fields;
	nrf_proxy.field_count = ARRAY_SIZE(fields);
	nrf_proxy.max_instance_count = MAX_INSTANCE_COUNT;
	nrf_proxy.create_cb = nrfcloud_proxy_create;
	lwm2m_register_obj(&nrf_proxy);

	return 0;
}

SYS_INIT(nrfcloud_proxy_init, APPLICATION, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);
