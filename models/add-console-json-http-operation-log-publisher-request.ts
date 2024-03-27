/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { AddSyslogJsonAuditLogPublisherRequestAllOf } from './add-syslog-json-audit-log-publisher-request-all-of';
import { ConsoleJsonHttpOperationLogPublisherShared } from './console-json-http-operation-log-publisher-shared';
import { EnumconsoleJsonHttpOperationLogPublisherSchemaUrn } from './enumconsole-json-http-operation-log-publisher-schema-urn';
import { EnumlogPublisherLogRequestHeadersProp } from './enumlog-publisher-log-request-headers-prop';
import { EnumlogPublisherLogRequestParametersProp } from './enumlog-publisher-log-request-parameters-prop';
import { EnumlogPublisherLogResponseHeadersProp } from './enumlog-publisher-log-response-headers-prop';
import { EnumlogPublisherLoggingErrorBehaviorProp } from './enumlog-publisher-logging-error-behavior-prop';
import { EnumlogPublisherOutputLocationProp } from './enumlog-publisher-output-location-prop';

/**
 * @type AddConsoleJsonHttpOperationLogPublisherRequest
 * @export
 */
export type AddConsoleJsonHttpOperationLogPublisherRequest = AddSyslogJsonAuditLogPublisherRequestAllOf & ConsoleJsonHttpOperationLogPublisherShared;


