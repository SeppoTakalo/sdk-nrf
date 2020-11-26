/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */
#include <zephyr.h>
#include <drivers/gpio.h>
#include <drivers/flash.h>
#include <nrf_modem.h>
#include <modem/lte_lc.h>
#include <modem/at_cmd.h>
#include <modem/at_notif.h>
#include <modem/nrf_modem_lib.h>
#include <modem/modem_key_mgmt.h>
#include <net/fota_download.h>
#include <net/socket.h>
#include <nrf_socket.h>
#include <dfu/mcuboot.h>
#include <nrf_fmfu.h>
#include <dfu/dfu_target_mcuboot.h>
#include <dfu/dfu_target_modem_full.h>
#include <dfu/fmfu_fdev.h>
#include <stdio.h>


#define LED_PORT DT_GPIO_LABEL(DT_ALIAS(led0), gpios)
#define TLS_SEC_TAG 42

static const struct device *gpiob;
static struct gpio_callback gpio_cb_b1;
static struct gpio_callback gpio_cb_b2;
static struct k_work fota_work;
static struct k_work fmfu_work;
static char modem_version[256];
static uint8_t fota_buf[NRF_FMFU_MODEM_BUFFER_SIZE];
static bool downloading_modem_firmware;

#ifndef CONFIG_USE_HTTPS
#define SEC_TAG (-1)
#else
#define SEC_TAG (TLS_SEC_TAG)
#endif

#define EXT_FLASH_DEVICE DT_LABEL(DT_INST(0, jedec_spi_nor))


/**@brief Recoverable modem library error. */
void nrf_modem_recoverable_error_handler(uint32_t err)
{
	printk("Modem library recoverable error: %u\n", err);
}

int cert_provision(void)
{
	static const char cert[] = {
		#include "../cert/BaltimoreCyberTrustRoot"
	};
	BUILD_ASSERT(sizeof(cert) < KB(4), "Certificate too large");
	int err;
	bool exists;
	uint8_t unused;

	err = modem_key_mgmt_exists(TLS_SEC_TAG,
				    MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN,
				    &exists, &unused);
	if (err) {
		printk("Failed to check for certificates err %d\n", err);
		return err;
	}

	if (exists) {
		/* For the sake of simplicity we delete what is provisioned
		 * with our security tag and reprovision our certificate.
		 */
		err = modem_key_mgmt_delete(TLS_SEC_TAG,
					    MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN);
		if (err) {
			printk("Failed to delete existing certificate, err %d\n",
			       err);
		}
	}

	printk("Provisioning certificate\n");

	/*  Provision certificate to the modem */
	err = modem_key_mgmt_write(TLS_SEC_TAG,
				   MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN,
				   cert, sizeof(cert) - 1);
	if (err) {
		printk("Failed to provision certificate, err %d\n", err);
		return err;
	}

	return 0;
}

static void print_modem_version(void)
{
	int err = at_cmd_write("AT+CGMR", modem_version, sizeof(modem_version),
				NULL);

	__ASSERT(err == 0, "Failed reading modem version");

	printk("Current modem firmware version: %s", modem_version);
}

/**@brief Start transfer of the file. */
static void app_dfu_transfer_start(struct k_work *unused)
{
	int retval;
	char *apn = NULL;

	retval = dfu_target_mcuboot_set_buf(fota_buf, sizeof(fota_buf));
	if (retval != 0) {
		printk("dfu_target_mcuboot_set_buf() failed, err %d\n", retval);
		return;
	}

	retval = fota_download_start(CONFIG_DOWNLOAD_HOST,
				     CONFIG_DOWNLOAD_FILE,
				     SEC_TAG,
				     apn,
				     0);
	if (retval != 0) {
		/* Re-enable button callback */
		gpio_pin_interrupt_configure(gpiob,
					     DT_GPIO_PIN(DT_ALIAS(sw0), gpios),
					     GPIO_INT_EDGE_TO_ACTIVE);

		printk("fota_download_start() failed, err %d\n", retval);
		return;
	}

}

static void apply_fmfu(void)
{
	int err;
	const struct device *flash_dev = device_get_binding(EXT_FLASH_DEVICE);

	err = libmodem_shutdown();
	if (err != 0) {
		printk("libmodem_shutdown() failed: %d\n", err);
		return;
	}

	err = fmfu_fdev_load(fota_buf, sizeof(fota_buf), flash_dev, 0);
	if (err != 0) {
		printk("fmfu_fdev_load failed: %d\n", err);
		return;
	}

	err = libmodem_init();
	if (err != 0) {
		printk("libmodem_init() failed: %d\n", err);
		return;
	}

	printk("Modem firmware update completed");
	print_modem_version();

}

static void fmfu_transfer_start(struct k_work *unused)
{
	const struct device *flash_dev;
	const char *file = CONFIG_DOWNLOAD_MODEM_0_FILE;
	int err;
	char *apn = NULL;

	printk("Started full modem firmware update\n");

	flash_dev = device_get_binding(EXT_FLASH_DEVICE);

	/* Pass 0 as size since that tells the stream_flash module
	 * that we want to use all the available flash in the device
	 */
	err = dfu_target_modem_full_cfg(fota_buf, sizeof(fota_buf), flash_dev,
					0, 0);
	if (err != 0) {
		printk("dfu_target_modem_full_cfg failed: %d\n", err);
		return;
	}

	/* Check if we should download modem 0 or 1 */
	if (strncmp(modem_version, CONFIG_DOWNLOAD_MODEM_0_VERSION,
		    strlen(CONFIG_DOWNLOAD_MODEM_0_VERSION)) == 0) {
		file = CONFIG_DOWNLOAD_MODEM_1_FILE;
	}

	printk("Downloading modem firmware %s\n", file);

	err = fota_download_start(CONFIG_DOWNLOAD_MODEM_HOST,
				  file, SEC_TAG, apn, 0);
	if (err != 0) {
		/* Re-enable button callback */
		gpio_pin_interrupt_configure(gpiob,
					     DT_GPIO_PIN(DT_ALIAS(sw1), gpios),
					     GPIO_INT_EDGE_TO_ACTIVE);

		printk("fota_download_start() failed, err %d\n",
			err);
		return;
	}

	downloading_modem_firmware = true;
}

/**@brief Turn on LED0 and LED1 if CONFIG_APPLICATION_VERSION
 * is 2 and LED0 otherwise.
 */
static int led_app_version(void)
{
	const struct device *dev;

	dev = device_get_binding(LED_PORT);
	if (dev == 0) {
		printk("Nordic nRF GPIO driver was not found!\n");
		return 1;
	}

	gpio_pin_configure(dev, DT_GPIO_PIN(DT_ALIAS(led0), gpios),
			   GPIO_OUTPUT_ACTIVE |
			   DT_GPIO_FLAGS(DT_ALIAS(led0), gpios));

#if CONFIG_APPLICATION_VERSION == 2
	gpio_pin_configure(dev, DT_GPIO_PIN(DT_ALIAS(led1), gpios),
			   GPIO_OUTPUT_ACTIVE |
			   DT_GPIO_FLAGS(DT_ALIAS(led1), gpios));
#endif
	return 0;
}

void dfu_button_pressed(const struct device *gpiob, struct gpio_callback *cb,
			uint32_t pins)
{
	k_work_submit(&fota_work);
	gpio_pin_interrupt_configure(gpiob, DT_GPIO_PIN(DT_ALIAS(sw0), gpios),
				     GPIO_INT_DISABLE);
}

void fmfu_button_pressed(const struct device *gpiob, struct gpio_callback *cb,
			 uint32_t pins)
{
	k_work_submit(&fmfu_work);
	gpio_pin_interrupt_configure(gpiob, DT_GPIO_PIN(DT_ALIAS(sw1), gpios),
				     GPIO_INT_DISABLE);
}

static int dfu_button_init(const char *label, gpio_pin_t pin,
			   gpio_flags_t flags, struct gpio_callback *cb,
			   gpio_callback_handler_t handler)
{
	int err;

	gpiob = device_get_binding(label);
	if (gpiob == 0) {
		printk("Nordic nRF GPIO driver was not found!\n");
		return 1;
	}
	err = gpio_pin_configure(gpiob, pin, GPIO_INPUT | flags);
	if (err != 0) {
		printk("gpio_pin_configure failed: %d\n", err);
		return err;
	}

	gpio_init_callback(cb, handler, BIT(pin));
	err = gpio_add_callback(gpiob, cb);
	if (err != 0) {
		printk("gpio_add_callback failed: %d\n", err);
		return err;
	}

	err = gpio_pin_interrupt_configure(gpiob, pin, GPIO_INT_EDGE_TO_ACTIVE);
	if (err != 0) {
		printk("gpio_pin_interrupt_configure failed: %d\n", err);
		return err;
	}

	return 0;

}

static int dfu_buttons_init(void)
{
	int err;

	err = dfu_button_init(DT_GPIO_LABEL(DT_ALIAS(sw0), gpios),
			      DT_GPIO_PIN(DT_ALIAS(sw0), gpios),
			      DT_GPIO_FLAGS(DT_ALIAS(sw0), gpios),
			      &gpio_cb_b1, dfu_button_pressed);
	if (err != 0) {
		printk("dfu_button_init failed for sw0: %d\n", err);
		return 1;
	}

	err = dfu_button_init(DT_GPIO_LABEL(DT_ALIAS(sw1), gpios),
			      DT_GPIO_PIN(DT_ALIAS(sw1), gpios),
			      DT_GPIO_FLAGS(DT_ALIAS(sw1), gpios),
			      &gpio_cb_b2, fmfu_button_pressed);
	if (err != 0) {
		printk("dfu_button_init failed for sw1: %d\n", err);
		return 1;
	}

	return 0;
}

void fota_dl_handler(const struct fota_download_evt *evt)
{
	switch (evt->id) {
	case FOTA_DOWNLOAD_EVT_ERROR:
		printk("Received error from fota_download\n");
		/* Fallthrough */
	case FOTA_DOWNLOAD_EVT_FINISHED:
		/* Re-enable button callback */
		gpio_pin_interrupt_configure(gpiob,
					     DT_GPIO_PIN(DT_ALIAS(sw0), gpios),
					     GPIO_INT_EDGE_TO_ACTIVE);
		gpio_pin_interrupt_configure(gpiob,
					     DT_GPIO_PIN(DT_ALIAS(sw1), gpios),
					     GPIO_INT_EDGE_TO_ACTIVE);

		if (downloading_modem_firmware) {
			apply_fmfu();
			downloading_modem_firmware = false;
		}

		break;

	default:
		break;
	}
}

/**@brief Configures modem to provide LTE link.
 *
 * Blocks until link is successfully established.
 */
static void modem_configure(void)
{
#if defined(CONFIG_LTE_LINK_CONTROL)
	BUILD_ASSERT(!IS_ENABLED(CONFIG_LTE_AUTO_INIT_AND_CONNECT),
			"This sample does not support auto init and connect");
	int err;
#if !defined(CONFIG_NRF_MODEM_LIB_SYS_INIT)
	/* Initialize AT only if nrf_modem_lib_init() is manually
	 * called by the main application
	 */
	err = at_notif_init();
	__ASSERT(err == 0, "AT Notify could not be initialized.");
	err = at_cmd_init();
	__ASSERT(err == 0, "AT CMD could not be established.");
#if defined(CONFIG_USE_HTTPS)
	err = cert_provision();
	__ASSERT(err == 0, "Could not provision root CA to %d", TLS_SEC_TAG);
#endif
#endif
	printk("LTE Link Connecting ...\n");
	err = lte_lc_init_and_connect();
	__ASSERT(err == 0, "LTE link could not be established.");
	printk("LTE Link Connected!\n");
#endif
	print_modem_version();
}

static int application_init(void)
{
	int err;

	k_work_init(&fota_work, app_dfu_transfer_start);
	k_work_init(&fmfu_work, fmfu_transfer_start);

	err = dfu_buttons_init();
	if (err != 0) {
		return err;
	}

	err = led_app_version();
	if (err != 0) {
		return err;
	}

	err = fota_download_init(fota_dl_handler);
	if (err != 0) {
		return err;
	}

	return 0;
}

void main(void)
{
	int err;

	printk("HTTP application update sample started\n");
	printk("Initializing modem library\n");
#if !defined(CONFIG_NRF_MODEM_LIB_SYS_INIT)
	err = nrf_modem_lib_init();
#else
	/* If nrf_modem_lib is initialized on post-kernel we should
	 * fetch the returned error code instead of nrf_modem_lib_init
	 */
	err = nrf_modem_lib_get_init_ret();
#endif
	switch (err) {
	case MODEM_DFU_RESULT_OK:
		printk("Modem firmware update successful!\n");
		printk("Modem will run the new firmware after reboot\n");
		k_thread_suspend(k_current_get());
		break;
	case MODEM_DFU_RESULT_UUID_ERROR:
	case MODEM_DFU_RESULT_AUTH_ERROR:
		printk("Modem firmware update failed\n");
		printk("Modem will run non-updated firmware on reboot.\n");
		break;
	case MODEM_DFU_RESULT_HARDWARE_ERROR:
	case MODEM_DFU_RESULT_INTERNAL_ERROR:
		printk("Modem firmware update failed\n");
		printk("Fatal error.\n");
		break;
	case -1:
		printk("Could not initialize momdem library.\n");
		printk("Fatal error.\n");
		return;
	default:
		break;
	}
	printk("Initialized modem library\n");

	/* START debug stuff */
	apply_fmfu();

	/* END debug stuff */

	modem_configure();

	boot_write_img_confirmed();


	err = application_init();
	if (err != 0) {
		return;
	}

	printk("Choose what upgrade to download:\n");
	printk("Press Button 1 for application firmware update\n");
	printk("Press Button 2 for full modem firmware update (fmfu)\n");
}
