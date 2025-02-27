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
import { EnumsmtpAlertHandlerSchemaUrn } from './enumsmtp-alert-handler-schema-urn';
import { SmtpAlertHandlerShared } from './smtp-alert-handler-shared';

/**
 * @type AddSmtpAlertHandlerRequest
 * @export
 */
export type AddSmtpAlertHandlerRequest = AddSmtpAlertHandlerRequestAllOf & SmtpAlertHandlerShared;


