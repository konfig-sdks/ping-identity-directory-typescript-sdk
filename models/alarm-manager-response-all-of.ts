/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumalarmManagerDefaultGaugeAlertLevelProp } from './enumalarm-manager-default-gauge-alert-level-prop';
import { EnumalarmManagerGeneratedAlertTypesProp } from './enumalarm-manager-generated-alert-types-prop';
import { EnumalarmManagerSchemaUrn } from './enumalarm-manager-schema-urn';
import { EnumalarmManagerSuppressedAlarmProp } from './enumalarm-manager-suppressed-alarm-prop';

/**
 * 
 * @export
 * @interface AlarmManagerResponseAllOf
 */
export interface AlarmManagerResponseAllOf {
    /**
     * 
     * @type {Array<EnumalarmManagerSchemaUrn>}
     * @memberof AlarmManagerResponseAllOf
     */
    'schemas'?: Array<EnumalarmManagerSchemaUrn>;
    /**
     * Specifies the level at which alerts are sent for alarms raised by the Alarm Manager.
     * @type {EnumalarmManagerDefaultGaugeAlertLevelProp}
     * @memberof AlarmManagerResponseAllOf
     */
    'defaultGaugeAlertLevel'?: EnumalarmManagerDefaultGaugeAlertLevelProp;
    /**
     * 
     * @type {Array<EnumalarmManagerGeneratedAlertTypesProp>}
     * @memberof AlarmManagerResponseAllOf
     */
    'generatedAlertTypes'?: Array<EnumalarmManagerGeneratedAlertTypesProp>;
    /**
     * 
     * @type {Array<EnumalarmManagerSuppressedAlarmProp>}
     * @memberof AlarmManagerResponseAllOf
     */
    'suppressedAlarm'?: Array<EnumalarmManagerSuppressedAlarmProp>;
}

