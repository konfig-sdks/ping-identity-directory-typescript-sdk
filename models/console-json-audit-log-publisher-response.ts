/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { ConsoleJsonAuditLogPublisherShared } from './console-json-audit-log-publisher-shared';
import { EnumconsoleJsonAuditLogPublisherSchemaUrn } from './enumconsole-json-audit-log-publisher-schema-urn';
import { EnumlogPublisherConsoleJsonAuditSoftDeleteEntryAuditBehaviorProp } from './enumlog-publisher-console-json-audit-soft-delete-entry-audit-behavior-prop';
import { EnumlogPublisherLoggingErrorBehaviorProp } from './enumlog-publisher-logging-error-behavior-prop';
import { EnumlogPublisherOutputLocationProp } from './enumlog-publisher-output-location-prop';
import { Meta } from './meta';
import { MetaMeta } from './meta-meta';
import { MetaUrnPingidentitySchemasConfigurationMessages20 } from './meta-urn-pingidentity-schemas-configuration-messages20';
import { SyslogJsonAuditLogPublisherResponseAllOf } from './syslog-json-audit-log-publisher-response-all-of';

/**
 * @type ConsoleJsonAuditLogPublisherResponse
 * @export
 */
export type ConsoleJsonAuditLogPublisherResponse = ConsoleJsonAuditLogPublisherShared & Meta & SyslogJsonAuditLogPublisherResponseAllOf;


