/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"


/**
 * Specifies the names of the alarm alert types that should be suppressed. If the condition that triggers an alarm in this list occurs, then the alarm will not be raised and no alerts will be generated. Only a subset of alarms can be suppressed in this way. Alarms triggered by a gauge can be disabled by disabling the gauge.
 * @export
 * @enum {string}
 */
export type EnumalarmManagerSuppressedAlarmProp = 'no-enabled-alert-handlers' | 'pdp-unavailable'

