/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { DebugAccessLogPublisherShared } from './debug-access-log-publisher-shared';
import { EnumdebugAccessLogPublisherSchemaUrn } from './enumdebug-access-log-publisher-schema-urn';
import { EnumlogPublisherCompressionMechanismProp } from './enumlog-publisher-compression-mechanism-prop';
import { EnumlogPublisherLoggingErrorBehaviorProp } from './enumlog-publisher-logging-error-behavior-prop';
import { Meta } from './meta';
import { MetaMeta } from './meta-meta';
import { MetaUrnPingidentitySchemasConfigurationMessages20 } from './meta-urn-pingidentity-schemas-configuration-messages20';
import { SyslogJsonAuditLogPublisherResponseAllOf } from './syslog-json-audit-log-publisher-response-all-of';

/**
 * @type DebugAccessLogPublisherResponse
 * @export
 */
export type DebugAccessLogPublisherResponse = DebugAccessLogPublisherShared & Meta & SyslogJsonAuditLogPublisherResponseAllOf;


