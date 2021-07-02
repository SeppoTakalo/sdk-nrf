.. _libmodem_fota_carrier_changelog:

Changelog
#########

FOTA library and sample applications for SoftBank.
All notable changes to this project are documented in this file.

Version 2.0-pre release Note
############################

Changes
*******
* SDK: ported to nRF Connect SDK 2.0
* Limit FOTA to devices attached to SoftBank home network only
* Cloud: Update nRF Cloud endpoint to current REST API
* Cloud: Use JWT tokens to authenticate. Requires provisioning. Requires modem FW 1.3.
* SDK: Add glue layer to SDK porting
* Allow library to autoinit
* Apply the modem update before rebooting
* Rename MODEM_FOTA to SB_FOTA
* Refactor application events

Supported SDK version
*********************
* nRF Connect SDK v2.0.0

Supported modem firmware
************************
* mfw_nrf9160_1.3.1

Version 1.1 Release Note
########################

Changes
*******
* SDK: ported to NCSv1.4.0
* Cloud: adapted to commercial FOTA server in nRF Connect for Cloud
* FOTA server is assigned with IP address instead of FQDN hostname

APN configuration
*****************
Same as 1.0

Supported SDK version
*********************
* nRF Connect SDK (NCS) v1.4.0

Supported modem firmware
************************

* mfw_nrf9160_1.2.2
* mfw_nrf9160_1.2.3

Supported REST API Host
************************
* https://api.nrfcloud.com/v1


Version 1.0 Release Note
########################

Changes
*******
* First release that is used to complete SBM IOT certification test

Supported SDK version
*********************
* nRF Connect SDK (NCS) v1.3.0

Supported modem firmware
************************
* mfw_nrf9160_1.2.2

Supported REST API Host
************************
* https://api.beta.nrfcloud.com/v1
