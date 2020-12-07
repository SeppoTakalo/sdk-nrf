.. _fmfu_smp_svr_sample:

Full modem update over SMP Server Sample
########################################

.. contents::
   :local:
   :depth: 2

The Full modem firmware update sample implements a Simple Management Protocol (SMP) server.
SMP is a basic transfer encoding for use with the MCUmgr management protocol.
For more information about MCUmgr and SMP, please see :ref:`device_mgmt`.

Requirements
************

The sample supports the following development kit:

.. table-from-rows:: /includes/sample_board_rows.txt
   :header: heading
   :rows: nrf9160dk_nrf9160ns

.. include:: /includes/spm.txt

Overview
********

The sample first deinitializes the :ref:`nrfxlib:nrf_modem`.
Next, it registers a stat command and firmware upload and get hash commands to
MCUMgr.

The sample then goes into and idle loop waiting for communication over the serial line.

Building and running
********************

.. |sample path| replace:: :file:`samples/nrf9160/fmfu_smp_svr`

.. include:: /includes/build_and_run_nrf9160.txt


Testing
=======

After programming the sample to your board, test it by performing the following steps:

1. Connect the USB cable and power on or reset your nRF9160 DK.
#. Open a terminal emulator and observe that the sample starts, close the terminal emulator. 
#. Call the provided :file:`update_modem.py` script with COM port, firmware ZIP file and UART baudrate.

Sample Output
=============

The python script should give the following output:

.. code-block:: console

   # nrf9160 modem firmware upgrade over serial port example started.
   {
   "duration": 406,
   "error_code": "Ok",
   "operation": "open_uart",
   "outcome": "success",
   "progress_percentage": 100
   }
   Programming modem bootloader.
   ...
   Finished with file.
   Verifying memory range 1 of 3
   Verifying memory range 2 of 3
   Verifying memory range 3 of 3
   Verification success.
   {
   "duration": 5,
   "error_code": "Ok",
   "operation": "close_uart",
   "outcome": "success",
   "progress_percentage": 100
   }
   ------------------------------------------------------------

Troubleshooting
===============

A way of testing if the sample is running correctly is to use the MCUMgr CLI tool.

.. code-block:: console
   mcumgr --conntype serial --connstring="dev=<COM Port>,baud=<Baudrate>" stat smp_com
   stat group: smp_com
       512 frame_max
       504 pack_max

Dependencies
************

This sample uses the following libraries:

From |NCS|
  * :ref:`mgmt_fmfu`
  * :ref:`modem_info`

From nrfxlib
  * :ref:`nrfxlib:nrf_modem`

In addition, it uses the following samples:

From |NCS|
  * :ref:`secure_partition_manager`
