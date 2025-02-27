/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { AddSyslogJsonAuditLogPublisherRequestAllOf } from './add-syslog-json-audit-log-publisher-request-all-of';
import { ConsoleJsonAuditLogPublisherShared } from './console-json-audit-log-publisher-shared';
import { EnumconsoleJsonAuditLogPublisherSchemaUrn } from './enumconsole-json-audit-log-publisher-schema-urn';
import { EnumlogPublisherConsoleJsonAuditSoftDeleteEntryAuditBehaviorProp } from './enumlog-publisher-console-json-audit-soft-delete-entry-audit-behavior-prop';
import { EnumlogPublisherLoggingErrorBehaviorProp } from './enumlog-publisher-logging-error-behavior-prop';
import { EnumlogPublisherOutputLocationProp } from './enumlog-publisher-output-location-prop';

/**
 * @type AddConsoleJsonAuditLogPublisherRequest
 * @export
 */
export type AddConsoleJsonAuditLogPublisherRequest = AddSyslogJsonAuditLogPublisherRequestAllOf & ConsoleJsonAuditLogPublisherShared;


