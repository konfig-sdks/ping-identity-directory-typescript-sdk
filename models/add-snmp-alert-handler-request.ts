/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { AddSmtpAlertHandlerRequestAllOf } from './add-smtp-alert-handler-request-all-of';
import { EnumalertHandlerDisabledAlertTypeProp } from './enumalert-handler-disabled-alert-type-prop';
import { EnumalertHandlerEnabledAlertSeverityProp } from './enumalert-handler-enabled-alert-severity-prop';
import { EnumalertHandlerEnabledAlertTypeProp } from './enumalert-handler-enabled-alert-type-prop';
import { EnumsnmpAlertHandlerSchemaUrn } from './enumsnmp-alert-handler-schema-urn';
import { SnmpAlertHandlerShared } from './snmp-alert-handler-shared';

/**
 * @type AddSnmpAlertHandlerRequest
 * @export
 */
export type AddSnmpAlertHandlerRequest = AddSmtpAlertHandlerRequestAllOf & SnmpAlertHandlerShared;


