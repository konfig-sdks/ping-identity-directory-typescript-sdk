/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { AddSyslogJsonAuditLogPublisherRequestAllOf } from './add-syslog-json-audit-log-publisher-request-all-of';
import { EnumlogPublisherCompressionMechanismProp } from './enumlog-publisher-compression-mechanism-prop';
import { EnumlogPublisherLoggingErrorBehaviorProp } from './enumlog-publisher-logging-error-behavior-prop';
import { EnumthirdPartyFileBasedAccessLogPublisherSchemaUrn } from './enumthird-party-file-based-access-log-publisher-schema-urn';
import { ThirdPartyFileBasedAccessLogPublisherShared } from './third-party-file-based-access-log-publisher-shared';

/**
 * @type AddThirdPartyFileBasedAccessLogPublisherRequest
 * @export
 */
export type AddThirdPartyFileBasedAccessLogPublisherRequest = AddSyslogJsonAuditLogPublisherRequestAllOf & ThirdPartyFileBasedAccessLogPublisherShared;


