.. zephyr:board:: nrf93m1dk_lm20b

Overview
********

The nRF93M1 DK version 0.5.0 is a development kit for the nRF93M1 cellular modem.
It uses the nRF54LM20B SoC as the host MCU.

.. note::

   The pin mapping is a work in progress.
   It is copied from the nRF93M1 DK version 0.4.0 (nRF54L15) and must be verified against the schematic.

Programming and debugging
*************************

.. zephyr:board-supported-runners::

Use the board target ``nrf93m1dk_lm20b/nrf54lm20b/cpuapp`` or ``nrf93m1dk_lm20b/nrf54lm20b/cpuapp/ns``
for the application core, and ``nrf93m1dk_lm20b/nrf54lm20b/cpuflpr`` for the FLPR core.
