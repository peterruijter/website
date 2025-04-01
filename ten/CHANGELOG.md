# Changelog

## Version 1.4.7.4
* BUGFIX: Anchor display for pages without articleId in URL

## Version 1.4.7.3
* BUGFIX: After premature termination of an ab test, sub-textareas were not reset

## Version 1.4.7.2
* BUGFIX: After premature termination of an ab test, new tests did not contain correct sub-id's

## Version 1.4.7.1
* BUGFIX: Headertest could not be started due to a missing article title

## Version 1.4.7.0
* Add support for splitted headers
* Add hasVideo parameter to datalayer Events

## Version 1.4.6.1
* Automated CI/CD pipeline for tentacles
* Added channel parameter support for video events

## Version 1.4.5.0 (2023-04-18)
* Changed xpath notation in linkClick and loyaltyClicks events to improve colors in the dashboard.

## Version 1.4.1 (2022-11-21)
* Removed sotm script instance from reading-time.js

## Version 1.2.0 (2022-11-21)
* In an SPA environment, the tentacle.js script is now loaded only once and not on every page change
* Tentacles has started using the more generic ingestion API (ingestion.js), but it still includes support for SOTM
  events. Remotely, settings by smartocto we will ensure that the switch to the Ingestion API is made. Events will then be sent to
  ingestion.smartocto.com.

## Version 1.1.3 (2022-11-21)
* Removed static forge.js and wgxpath.js scripts that are now integrated in the tentacle.js script

