/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>
#include <stdio.h>
#include <nrf_modem.h>
#include <zephyr/drivers/flash.h>
#include <dfu/dfu_target.h>
#include <dfu/dfu_target_mcuboot.h>
#include <zephyr/dfu/mcuboot.h>
#include <zephyr/logging/log_ctrl.h>
#include <zephyr/net/lwm2m.h>
#include <modem/nrf_modem_lib.h>
#include <zephyr/sys/reboot.h>
#include <net/fota_download.h>
#include <net/lwm2m_client_utils.h>
#include <net/lwm2m_client_utils_fota.h>
/* Firmware update needs access to internal functions as well */
#include <lwm2m_engine.h>

#if defined(CONFIG_DFU_TARGET_FULL_MODEM)
#include <dfu/dfu_target_full_modem.h>
#include <nrf_modem_full_dfu.h>
#include <dfu/fmfu_fdev.h>
#include <string.h>
#endif

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(lwm2m_firmware, CONFIG_LWM2M_CLIENT_UTILS_LOG_LEVEL);

#define BYTE_PROGRESS_STEP (1024 * 10)
#define REBOOT_DELAY K_SECONDS(1)

static lwm2m_firmware_get_update_state_cb_t update_state_cb;
static uint8_t firmware_buf[CONFIG_LWM2M_COAP_BLOCK_SIZE];

#if defined(CONFIG_DFU_TARGET_FULL_MODEM)
static uint8_t fmfu_buf[1024];
static const struct device *flash_dev = DEVICE_DT_GET_ONE(jedec_spi_nor);
static struct k_work full_modem_update_work;
#endif

#ifdef CONFIG_DFU_TARGET_MCUBOOT
static uint8_t mcuboot_buf[CONFIG_LWM2M_CLIENT_UTILS_MCUBOOT_FLASH_BUF_SIZE] __aligned(4);
#endif
#define UNUSED_OBJ_ID 0xffff
static uint16_t ongoing_obj_id;
static int image_type = DFU_TARGET_IMAGE_TYPE_ANY;
static char *fota_path;
static char *fota_host;
static int fota_sec_tag;
static uint8_t percent_downloaded;
static uint32_t bytes_downloaded;
static int application_obj_id;
static int modem_obj_id;

static struct update_data {
	struct k_work_delayable work;
	enum {APP, MODEM_DELTA, MODEM_FULL} type;
} update_data;
static struct k_work download_work;

void client_acknowledge(void);

NRF_MODEM_LIB_ON_INIT(lwm2m_firmware_init_hook,
		      on_modem_lib_init, NULL);

/* Initialized to value different than success (0) */
static int modem_lib_init_result = -1;

static void on_modem_lib_init(int ret, void *ctx)
{
	modem_lib_init_result = ret;
}

/************** Wrappers between normal FOTA object and Advanced FOTA object ********/

static uint8_t get_state(uint16_t id) {
	if (IS_ENABLED(CONFIG_LWM2M_CLIENT_UTILS_ADV_FIRMWARE_UPDATE_OBJ_SUPPORT)) {
		return lwm2m_adv_firmware_get_update_state(id);
	} else {
#if defined(CONFIG_LWM2M_FIRMWARE_UPDATE_OBJ_SUPPORT)
		return lwm2m_firmware_get_update_state_inst(id);
#else
		return 0;
#endif
	}
}

static void set_state(uint16_t id, uint8_t state) {
	if (IS_ENABLED(CONFIG_LWM2M_CLIENT_UTILS_ADV_FIRMWARE_UPDATE_OBJ_SUPPORT)) {
		lwm2m_adv_firmware_set_update_state(id, state);
	} else {
#if defined(CONFIG_LWM2M_FIRMWARE_UPDATE_OBJ_SUPPORT)
		lwm2m_firmware_set_update_state_inst(id, state);
#endif
	}
}

static void set_result(uint16_t id, uint8_t result)
{
	if (IS_ENABLED(CONFIG_LWM2M_CLIENT_UTILS_ADV_FIRMWARE_UPDATE_OBJ_SUPPORT)) {
		lwm2m_adv_firmware_set_update_result(id, result);
	} else {
#if defined(CONFIG_LWM2M_FIRMWARE_UPDATE_OBJ_SUPPORT)
		lwm2m_firmware_set_update_result_inst(id, result);
#endif
	}
}

#if defined(CONFIG_DFU_TARGET_FULL_MODEM)
static void apply_fmfu_from_ext_flash(struct k_work *work)
{
	int ret;

	LOG_INF("Applying full modem firmware update from external flash\n");

	ret = nrf_modem_lib_shutdown();
	if (ret != 0) {
		LOG_ERR("nrf_modem_lib_shutdown() failed: %d\n", ret);
		return;
	}

	ret = nrf_modem_lib_init(FULL_DFU_MODE);
	if (ret != 0) {
		LOG_ERR("nrf_modem_lib_init(FULL_DFU_MODE) failed: %d\n", ret);
		return;
	}

	ret = fmfu_fdev_load(fmfu_buf, sizeof(fmfu_buf), flash_dev, 0);
	if (ret != 0) {
		LOG_ERR("fmfu_fdev_load failed: %d\n", ret);
		return;
	}
	LOG_INF("Modem firmware update completed\n");

	k_work_schedule(&update_data.work, REBOOT_DELAY);
}

static int configure_full_modem_update(void)
{
	int ret = 0;

	if (!device_is_ready(flash_dev)) {
		LOG_ERR("Flash device not ready: %s\n", flash_dev->name);
	}

	const struct dfu_target_full_modem_params params = {
		.buf = fmfu_buf,
		.len = sizeof(fmfu_buf),
		.dev = &(struct dfu_target_fmfu_fdev){ .dev = flash_dev,
							.offset = 0,
							.size = 0 }
	};

	ret = dfu_target_full_modem_cfg(&params);
	if (ret != 0 && ret != -EALREADY) {
		LOG_ERR("dfu_target_full_modem_cfg failed: %d\n", ret);
	} else {
		ret = 0;
	}

	return ret;
}
#endif

static void update_work_handler(struct k_work *work)
{
	int ret;
	if (IS_ENABLED(CONFIG_LWM2M_CLIENT_UTILS_FIRMWARE_UPDATE_REBOOT) && update_data.type == APP) {
		LOG_INF("Rebooting device");
		//TODO: Call reboot handler from device object.
		sys_reboot(SYS_REBOOT_COLD);
	} else if (update_data.type == MODEM_DELTA) {
		//TODO: Create function from this
		enum lte_lc_func_mode mode;
		lte_lc_func_mode_get(&mode);
		if (mode != LTE_LC_FUNC_MODE_POWER_OFF) {
			ret = lte_lc_func_mode_set(LTE_LC_FUNC_MODE_POWER_OFF);
			LOG_DBG("lte_lc_func_mode_set() -> %d", ret);
			k_work_schedule(&update_data.work, K_SECONDS(5));
			LOG_DBG("Rescheduling update");
		} else {
			ret = lte_lc_deinit();
			LOG_DBG("lte_lc_deinit() -> %d", ret);
			ret = nrf_modem_lib_shutdown();
			LOG_DBG("nrf_modem_lib_shutdown() -> %d", ret);
			ret = nrf_modem_lib_init(NORMAL_MODE);
			LOG_DBG("nrf_modem_lib_init(NORMAL_MODE) -> %d", ret);
			ret = nrf_modem_lib_shutdown();
			LOG_DBG("nrf_modem_lib_shutdown() -> %d", ret);
			ret = nrf_modem_lib_init(NORMAL_MODE);
			LOG_DBG("nrf_modem_lib_init(NORMAL_MODE) -> %d", ret);
			ret = lte_lc_normal();
			LOG_DBG("lte_lc_normal() -> %d", ret);
		}
	} else if (update_data.type == MODEM_FULL) {
#if defined(CONFIG_DFU_TARGET_FULL_MODEM)
		apply_fmfu_from_ext_flash(NULL);
#endif
	}
}

static int firmware_update_cb(uint16_t obj_inst_id, uint8_t *args,
			    uint16_t args_len)
{
	ARG_UNUSED(args);
	ARG_UNUSED(args_len);

	set_state(obj_inst_id, 3);

	LOG_DBG("Executing firmware update");
	if (obj_inst_id == modem_obj_id) {
		if (image_type == DFU_TARGET_IMAGE_TYPE_FULL_MODEM) {
			update_data.type = MODEM_FULL;
		} else {
			update_data.type = MODEM_DELTA;
		}
	} else {
		update_data.type = APP;
	}

	k_work_schedule(&update_data.work, REBOOT_DELAY);

	return 0;
}


static void *firmware_get_buf(uint16_t obj_inst_id, uint16_t res_id,
			      uint16_t res_inst_id, size_t *data_len)
{
	*data_len = sizeof(firmware_buf);
	return firmware_buf;
}

static int firmware_update_state(uint16_t obj_inst_id, uint16_t res_id,
				 uint16_t res_inst_id, uint8_t *data,
				 uint16_t data_len, bool last_block,
				 size_t total_size)
{
	if (update_state_cb) {
		update_state_cb(*data);
	}

	if (*data == STATE_IDLE) {
		fota_download_cancel();
		int ret = dfu_target_reset();

		if (ret < 0) {
			LOG_ERR("Failed to reset DFU target, err: %d", ret);
			return ret;
		}

		percent_downloaded = 0;
		bytes_downloaded = 0;
		ongoing_obj_id = UNUSED_OBJ_ID;
	}

	return 0;
}


static void dfu_target_cb(enum dfu_target_evt_id evt)
{
	ARG_UNUSED(evt);
}

static int firmware_block_received_cb(uint16_t obj_inst_id,
				      uint16_t res_id, uint16_t res_inst_id,
				      uint8_t *data, uint16_t data_len,
				      bool last_block, size_t total_size)
{
	uint8_t curent_percent;
	uint32_t current_bytes;
	size_t offset;
	size_t skip = 0;
	int ret = 0;

	if (!data_len) {
		LOG_ERR("Data len is zero, nothing to write.");
		return -EINVAL;
	}

	if (bytes_downloaded == 0) {
		client_acknowledge();

		image_type = dfu_target_img_type(data, data_len);
		if (image_type == -ENOTSUP) {
			ret = -ENOMSG; /* Translates to unsupported image type */
			goto cleanup;
		}
		LOG_INF("Image type %d", image_type);
#if defined(CONFIG_DFU_TARGET_FULL_MODEM)
		if (image_type == DFU_TARGET_IMAGE_TYPE_FULL_MODEM) {
			configure_full_modem_update();
		}
#endif
		ret = dfu_target_init(image_type, 0, total_size, dfu_target_cb);
		if (ret < 0) {
			LOG_ERR("Failed to init DFU target, err: %d", ret);
			goto cleanup;
		}

		LOG_INF("%s firmware download started.",
			image_type == DFU_TARGET_IMAGE_TYPE_MODEM_DELTA ||
			image_type == DFU_TARGET_IMAGE_TYPE_FULL_MODEM ?
				"Modem" :
				"Application");
	}

	ret = dfu_target_offset_get(&offset);
	if (ret < 0) {
		LOG_ERR("Failed to obtain current offset, err: %d", ret);
		goto cleanup;
	}

	/* Display a % downloaded or byte progress, if no total size was
	 * provided (this can happen in PULL mode FOTA)
	 */
	if (total_size > 0) {
		curent_percent = bytes_downloaded * 100 / total_size;
		if (curent_percent > percent_downloaded) {
			percent_downloaded = curent_percent;
			LOG_INF("Downloaded %d%%", percent_downloaded);
		}
	} else {
		current_bytes = bytes_downloaded + data_len;
		if (current_bytes / BYTE_PROGRESS_STEP >
		    bytes_downloaded / BYTE_PROGRESS_STEP) {
			LOG_INF("Downloaded %d kB", current_bytes / 1024);
		}
	}

	if (bytes_downloaded < offset) {
		skip = MIN(data_len, offset - bytes_downloaded);

		LOG_INF("Skipping bytes %d-%d, already written.",
			bytes_downloaded, bytes_downloaded + skip);
	}

	bytes_downloaded += data_len;

	if (skip == data_len) {
		/* Nothing to do. */
		return 0;
	}

	ret = dfu_target_write(data + skip, data_len - skip);
	if (ret < 0) {
		LOG_ERR("dfu_target_write error, err %d", ret);
		goto cleanup;
	}

	if (last_block) {
		/* Last write to flash should be flush write */
		ret = dfu_target_done(true);
		if (ret == 0) {
			ret = dfu_target_schedule_update(0);
		}

		if (ret < 0) {
			LOG_ERR("dfu_target_done error, err %d", ret);
			goto cleanup;
		}
		LOG_INF("Firmware downloaded, %d bytes in total",
			bytes_downloaded);
	} else {
		/* Keep going */
		return 0;
	}

	if (total_size && (bytes_downloaded != total_size)) {
		LOG_ERR("Early last block, downloaded %d, expecting %d",
			bytes_downloaded, total_size);
		ret = -EIO;
	}

cleanup:
	if (ret < 0) {
		if (dfu_target_reset() < 0) {
			LOG_ERR("Failed to reset DFU target");
		}
	}

	bytes_downloaded = 0;
	percent_downloaded = 0;

	return ret;
}

static void fota_download_callback(const struct fota_download_evt *evt)
{
	switch (evt->id) {
	/* These two cases return immediately */
	case FOTA_DOWNLOAD_EVT_PROGRESS:
		LOG_DBG("DL progress %d", evt->progress);
		return;
	default:
		return;

	/* Following cases mark end of FOTA download */
	case FOTA_DOWNLOAD_EVT_CANCELLED:
		LOG_ERR("FOTA_DOWNLOAD_EVT_CANCELLED");
		set_result(ongoing_obj_id, RESULT_CONNECTION_LOST);
		break;
	case FOTA_DOWNLOAD_EVT_ERROR:
		LOG_ERR("FOTA_DOWNLOAD_EVT_ERROR");
		switch (evt->cause) {
		/* No error, used when event ID is not FOTA_DOWNLOAD_EVT_ERROR. */
		case FOTA_DOWNLOAD_ERROR_CAUSE_NO_ERROR:
			set_result(ongoing_obj_id, RESULT_CONNECTION_LOST);
			break;
		/* Downloading the update failed. The download may be retried. */
		case FOTA_DOWNLOAD_ERROR_CAUSE_DOWNLOAD_FAILED:
			set_result(ongoing_obj_id, RESULT_CONNECTION_LOST);
			break;
		/* The update is invalid and was rejected. Retry will not help. */
		case FOTA_DOWNLOAD_ERROR_CAUSE_INVALID_UPDATE:
			/* FALLTHROUGH */
		/* Actual firmware type does not match expected. Retry will not help. */
		case FOTA_DOWNLOAD_ERROR_CAUSE_TYPE_MISMATCH:
			set_result(ongoing_obj_id, RESULT_UNSUP_FW);
			break;
		default:
			set_result(ongoing_obj_id, RESULT_UPDATE_FAILED);
			break;
		}
		break;
	case FOTA_DOWNLOAD_EVT_FINISHED:
		image_type = fota_download_target();
		LOG_INF("FOTA download finished, target %d", image_type);
		set_state(ongoing_obj_id, STATE_DOWNLOADED);
		break;
	}
	k_free(fota_host);
	fota_host = NULL;
	fota_path = NULL;
	ongoing_obj_id = UNUSED_OBJ_ID;
}

static void start_fota_download(struct k_work *work)
{
	int ret;

#if defined(CONFIG_DFU_TARGET_FULL_MODEM)
	/* We can't know if the download is full modem firmware
	 * before the downloader actually starts, so configure
	 * the dfu_target_full_modem here
	 */
	ret = configure_full_modem_update();
	if (ret) {
		LOG_ERR("configure_full_modem_update() failed, return code %d", ret);
		set_result(ongoing_obj_id, RESULT_NO_STORAGE);
		goto err;
	}
#endif

	enum dfu_target_image_type type;
	if (IS_ENABLED(CONFIG_LWM2M_CLIENT_UTILS_ADV_FIRMWARE_UPDATE_OBJ_SUPPORT)) {
		if (ongoing_obj_id == modem_obj_id) {
			type = DFU_TARGET_IMAGE_TYPE_MODEM_DELTA;
		} else {
			type = DFU_TARGET_IMAGE_TYPE_MCUBOOT;
		}
	} else {
		type = DFU_TARGET_IMAGE_TYPE_ANY;
	}

	ret = fota_download_start_with_image_type(fota_host, fota_path, fota_sec_tag, 0, 0, type);
	if (ret) {
		LOG_ERR("fota_download_start() failed, return code %d", ret);
		set_result(ongoing_obj_id, RESULT_CONNECTION_LOST);
		goto err;
	}

	return;

err:
	k_free(fota_host);
	fota_host = NULL;
	fota_path = NULL;
	ongoing_obj_id = UNUSED_OBJ_ID;
	return;
}

static int init_start_download(char *uri)
{
	int ret;

	ret = fota_download_init(fota_download_callback);
	if (ret != 0) {
		LOG_ERR("fota_download_init() returned %d", ret);
		return -EBUSY;
	}

	bool is_tls = strncmp(uri, "https://", 8) == 0 || strncmp(uri, "coaps://", 8) == 0;
	if (is_tls) {
		fota_sec_tag = CONFIG_LWM2M_CLIENT_UTILS_DOWNLOADER_SEC_TAG;
	} else {
		fota_sec_tag = -1;
	}

	/* Find the end of protocol marker https:// or coap:// */
	char *s = strstr(uri, "://");

	if (!s) {
		LOG_ERR("Host not found");
		return -EINVAL;
	}
	s += strlen("://");

	/* Find the end of host name, which is start of path */
	char *e = strchr(s, '/');

	if (!e) {
		LOG_ERR("Path not found");
		return -EINVAL;
	}

	/* Path can point to a string, which is kept in LwM2M engine's memory */
	fota_path = e + 1; /* Skip the '/' from path */
	int len = e - uri;

	/* For host, I need to allocate space, as I need to copy the substring */
	fota_host = k_malloc(len + 1);
	if (!fota_host) {
		LOG_ERR("Failed to allocate memory");
		return -ENOMEM;
	}
	strncpy(fota_host, uri, len);
	fota_host[len] = 0;

	k_work_submit(&download_work);

	return 0;
}

static int write_dl_uri(uint16_t obj_inst_id, uint16_t res_id, uint16_t res_inst_id, uint8_t *data,
			uint16_t data_len, bool last_block, size_t total_size)
{
	int ret;
	char *package_uri = (char *)data;
	uint8_t state;

	LOG_DBG("write URI: %s", package_uri);

	state = get_state(obj_inst_id);

	if (state == STATE_IDLE && data_len > 0) {
		set_state(obj_inst_id, STATE_DOWNLOADING);

		if (ongoing_obj_id == UNUSED_OBJ_ID) {
			ongoing_obj_id = obj_inst_id;
			ret = init_start_download(package_uri);
			switch (ret) {
			case 0:
				/* OK */
				break;
			case -EINVAL:
				set_result(obj_inst_id, RESULT_INVALID_URI);
				ongoing_obj_id = UNUSED_OBJ_ID;
				break;
			case -EBUSY:
				/* Failed to init MCUBoot or download client */
				set_result(obj_inst_id, RESULT_NO_STORAGE);
				ongoing_obj_id = UNUSED_OBJ_ID;
				break;
			default: /* Remaining errors from init_start_download() are mostly
				  * reflected by OUT OF MEMORY situations
				  */
				set_result(obj_inst_id, RESULT_OUT_OF_MEM);
				ongoing_obj_id = UNUSED_OBJ_ID;
			}
		}
	} else {
		/* reset to state idle and result default */
		set_result(obj_inst_id, RESULT_DEFAULT);
	}

	return 0;
}

int lwm2m_firmware_apply_update(uint16_t obj_inst_id)
{
	int ret = 0;

	if (get_state(obj_inst_id) == STATE_UPDATING) {
		ret = firmware_update_cb(obj_inst_id, NULL, 0);
	} else {
		LOG_ERR("No updates scheduled for instance %d", obj_inst_id);
		ret = -EINVAL;
	}

	return ret;
}

void lwm2m_firmware_set_update_state_cb(lwm2m_firmware_get_update_state_cb_t cb)
{
	update_state_cb = cb;
}

int lwm2m_init_firmware(void)
{
	k_work_init_delayable(&update_data.work, update_work_handler);
	k_work_init(&download_work, start_fota_download);
#if defined(CONFIG_DFU_TARGET_FULL_MODEM)
	k_work_init(&full_modem_update_work, apply_fmfu_from_ext_flash);
#endif
	ongoing_obj_id = UNUSED_OBJ_ID;
	/* setup data buffer for block-wise transfer */
	if (IS_ENABLED(CONFIG_LWM2M_CLIENT_UTILS_ADV_FIRMWARE_UPDATE_OBJ_SUPPORT)) {
		application_obj_id = lwm2m_adv_firmware_create_inst("application", firmware_get_buf, write_dl_uri, firmware_block_received_cb, firmware_update_cb, firmware_update_state);
		modem_obj_id = lwm2m_adv_firmware_create_inst("modem:" CONFIG_SOC, firmware_get_buf, write_dl_uri, firmware_block_received_cb, firmware_update_cb, firmware_update_state);
	} else {
/*		lwm2m_firmware_set_update_cb(firmware_update_cb);
		lwm2m_engine_register_pre_write_callback("5/0/0", firmware_get_buf);
		lwm2m_engine_register_post_write_callback("5/0/1", write_dl_uri);
		lwm2m_engine_register_post_write_callback("5/0/3", firmware_update_state);
		lwm2m_firmware_set_write_cb(firmware_block_received_cb);*/
	}
	return 0;
}

void lwm2m_verify_modem_fw_update(void)
{
	if (!IS_ENABLED(CONFIG_LWM2M_CLIENT_UTILS_ADV_FIRMWARE_UPDATE_OBJ_SUPPORT)) {
		struct update_counter counter;

		/* Handle return values relating to modem firmware update */
		int ret = modem_lib_init_result;
		switch (ret) {
		case MODEM_DFU_RESULT_OK:
			LOG_INF("MODEM UPDATE OK. Will run new firmware");

			ret = fota_settings_init();
			if (ret < 0 && ret != -EALREADY) {
				LOG_WRN("Unable to init settings (%d)", ret);
				break;
			}

			ret = fota_update_counter_read(&counter);
			if (ret != 0) {
				LOG_ERR("Failed read the update counter, err: %d", ret);
				break;
			}

			if (counter.update != -1) {
				ret = fota_update_counter_update(COUNTER_CURRENT,
								counter.update);
				if (ret != 0) {
					LOG_ERR("Failed to update the update counter, err: %d",
						ret);
				}
			}

			break;

		case MODEM_DFU_RESULT_UUID_ERROR:
		case MODEM_DFU_RESULT_AUTH_ERROR:
			LOG_ERR("MODEM UPDATE ERROR %d. Will run old firmware", ret);
			break;

		case MODEM_DFU_RESULT_HARDWARE_ERROR:
		case MODEM_DFU_RESULT_INTERNAL_ERROR:
			LOG_ERR("MODEM UPDATE FATAL ERROR %d. Modem failiure", ret);
			break;

		default:
			return;
		}

		k_work_schedule(&update_data.work, K_NO_WAIT);
	}
}

int lwm2m_init_image(void)
{
	int ret;

	if (!IS_ENABLED(CONFIG_LWM2M_CLIENT_UTILS_ADV_FIRMWARE_UPDATE_OBJ_SUPPORT)) {
		struct update_counter counter;
		bool image_ok;

		/* Update boot status and update counter */
		ret = fota_update_counter_read(&counter);
		if (ret) {
			LOG_ERR("Failed read update counter");
			return ret;
		}
		LOG_INF("Update Counter: current %d, update %d",
			counter.current, counter.update);
		image_ok = boot_is_img_confirmed();
		LOG_INF("Image is%s confirmed OK", image_ok ? "" : " not");
		if (!image_ok) {
			ret = boot_write_img_confirmed();
			if (ret) {
				LOG_ERR("Couldn't confirm this image: %d", ret);
				return ret;
			}

			LOG_INF("Marked image as OK");

			if (counter.update != -1) {
				ret = fota_update_counter_update(COUNTER_CURRENT,
								counter.update);
				if (ret) {
					LOG_ERR("Failed to update the update "
						"counter: %d", ret);
					return ret;
				}

				ret = fota_update_counter_read(&counter);
				if (ret) {
					LOG_ERR("Failed to read update counter: %d",
						ret);
					return ret;
				}

				LOG_INF("Update Counter updated");
			}
		}

		/* Check if a firmware update status needs to be reported */
		if (counter.update != -1 && counter.current == counter.update) {
			/* Successful update */
			LOG_INF("Firmware updated successfully");
			lwm2m_engine_set_u8("5/0/5", RESULT_SUCCESS);
		} else if (counter.update > counter.current) {
			/* Failed update */
			LOG_INF("Firmware failed to be updated");
			lwm2m_engine_set_u8("5/0/5", RESULT_UPDATE_FAILED);
		}
	}
#ifdef CONFIG_DFU_TARGET_MCUBOOT
	/* Set the required buffer for MCUboot targets */
	ret = dfu_target_mcuboot_set_buf(mcuboot_buf, sizeof(mcuboot_buf));
	if (ret) {
		LOG_ERR("Failed to set MCUboot flash buffer %d", ret);
	}
#endif

	return ret;
}
