/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumalertHandlerDisabledAlertTypeProp } from './enumalert-handler-disabled-alert-type-prop';
import { EnumalertHandlerEnabledAlertSeverityProp } from './enumalert-handler-enabled-alert-severity-prop';
import { EnumalertHandlerEnabledAlertTypeProp } from './enumalert-handler-enabled-alert-type-prop';
import { EnumsnmpSubAgentAlertHandlerSchemaUrn } from './enumsnmp-sub-agent-alert-handler-schema-urn';

/**
 * 
 * @export
 * @interface SnmpSubAgentAlertHandlerShared
 */
export interface SnmpSubAgentAlertHandlerShared {
    /**
     * A description for this Alert Handler
     * @type {string}
     * @memberof SnmpSubAgentAlertHandlerShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumsnmpSubAgentAlertHandlerSchemaUrn>}
     * @memberof SnmpSubAgentAlertHandlerShared
     */
    'schemas': Array<EnumsnmpSubAgentAlertHandlerSchemaUrn>;
    /**
     * Indicates whether the server should attempt to invoke this SNMP Sub Agent Alert Handler in a background thread so that any potentially-expensive processing (e.g., performing network communication to deliver the alert notification) will not delay whatever processing the server was performing when the alert was generated.
     * @type {boolean}
     * @memberof SnmpSubAgentAlertHandlerShared
     */
    'asynchronous'?: boolean;
    /**
     * Indicates whether the Alert Handler is enabled.
     * @type {boolean}
     * @memberof SnmpSubAgentAlertHandlerShared
     */
    'enabled': boolean;
    /**
     * 
     * @type {Array<EnumalertHandlerEnabledAlertSeverityProp>}
     * @memberof SnmpSubAgentAlertHandlerShared
     */
    'enabledAlertSeverity'?: Array<EnumalertHandlerEnabledAlertSeverityProp>;
    /**
     * 
     * @type {Array<EnumalertHandlerEnabledAlertTypeProp>}
     * @memberof SnmpSubAgentAlertHandlerShared
     */
    'enabledAlertType'?: Array<EnumalertHandlerEnabledAlertTypeProp>;
    /**
     * 
     * @type {Array<EnumalertHandlerDisabledAlertTypeProp>}
     * @memberof SnmpSubAgentAlertHandlerShared
     */
    'disabledAlertType'?: Array<EnumalertHandlerDisabledAlertTypeProp>;
}

