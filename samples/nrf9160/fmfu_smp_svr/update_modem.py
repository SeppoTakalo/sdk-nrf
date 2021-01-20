import sys
import argparse
import logging
import time
import os
from pynrfjprog import HighLevel

def run(uart, modem_firmware_zip, baudrate):
    if not os.path.exists(modem_firmware_zip):
        raise Exception("Modem firmware zip file does not exist")
    print('# nrf9160 modem firmware upgrade over serial port example started.')

    # Configure logging to see HighLevel API output
    logging.basicConfig(level=logging.DEBUG, format="%(message)s")

    # Find the hex file to flash. It should be located in the same directory as
    # this example file.
    with HighLevel.API() as api:
        start_time = time.time()
        with HighLevel.ModemUARTDFUProbe(api, uart, baudrate) as modem_dfu_probe:
            modem_dfu_probe.program(modem_firmware_zip)
            modem_dfu_probe.verify(modem_firmware_zip)

        # Print upload time
        print("------------------------------------------------------------")
        print("The operation took {0:.2f} seconds ".format(time.time() - start_time))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("firmware", default=None, help="Path to nrf9160 modem firmware zip folder")
    parser.add_argument("uart", default=None, help="Serial device name for UART")
    parser.add_argument("baudrate", default=115200, help="Baud rate of UART communication", type=int)
    args = parser.parse_args()
    run(args.uart, args.firmware, args.baudrate)

