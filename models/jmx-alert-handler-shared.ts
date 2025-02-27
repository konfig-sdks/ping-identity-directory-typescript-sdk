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
import { EnumjmxAlertHandlerSchemaUrn } from './enumjmx-alert-handler-schema-urn';

/**
 * 
 * @export
 * @interface JmxAlertHandlerShared
 */
export interface JmxAlertHandlerShared {
    /**
     * A description for this Alert Handler
     * @type {string}
     * @memberof JmxAlertHandlerShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumjmxAlertHandlerSchemaUrn>}
     * @memberof JmxAlertHandlerShared
     */
    'schemas': Array<EnumjmxAlertHandlerSchemaUrn>;
    /**
     * Indicates whether the server should attempt to invoke this JMX Alert Handler in a background thread so that any potentially-expensive processing (e.g., performing network communication to deliver the alert notification) will not delay whatever processing the server was performing when the alert was generated.
     * @type {boolean}
     * @memberof JmxAlertHandlerShared
     */
    'asynchronous'?: boolean;
    /**
     * Indicates whether the Alert Handler is enabled.
     * @type {boolean}
     * @memberof JmxAlertHandlerShared
     */
    'enabled': boolean;
    /**
     * 
     * @type {Array<EnumalertHandlerEnabledAlertSeverityProp>}
     * @memberof JmxAlertHandlerShared
     */
    'enabledAlertSeverity'?: Array<EnumalertHandlerEnabledAlertSeverityProp>;
    /**
     * 
     * @type {Array<EnumalertHandlerEnabledAlertTypeProp>}
     * @memberof JmxAlertHandlerShared
     */
    'enabledAlertType'?: Array<EnumalertHandlerEnabledAlertTypeProp>;
    /**
     * 
     * @type {Array<EnumalertHandlerDisabledAlertTypeProp>}
     * @memberof JmxAlertHandlerShared
     */
    'disabledAlertType'?: Array<EnumalertHandlerDisabledAlertTypeProp>;
}

