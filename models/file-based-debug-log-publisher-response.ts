/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumfileBasedDebugLogPublisherSchemaUrn } from './enumfile-based-debug-log-publisher-schema-urn';
import { EnumlogPublisherCompressionMechanismProp } from './enumlog-publisher-compression-mechanism-prop';
import { EnumlogPublisherDefaultDebugCategoryProp } from './enumlog-publisher-default-debug-category-prop';
import { EnumlogPublisherDefaultDebugLevelProp } from './enumlog-publisher-default-debug-level-prop';
import { EnumlogPublisherLoggingErrorBehaviorProp } from './enumlog-publisher-logging-error-behavior-prop';
import { EnumlogPublisherTimestampPrecisionProp } from './enumlog-publisher-timestamp-precision-prop';
import { FileBasedDebugLogPublisherShared } from './file-based-debug-log-publisher-shared';
import { Meta } from './meta';
import { MetaMeta } from './meta-meta';
import { MetaUrnPingidentitySchemasConfigurationMessages20 } from './meta-urn-pingidentity-schemas-configuration-messages20';
import { SyslogJsonAuditLogPublisherResponseAllOf } from './syslog-json-audit-log-publisher-response-all-of';

/**
 * @type FileBasedDebugLogPublisherResponse
 * @export
 */
export type FileBasedDebugLogPublisherResponse = FileBasedDebugLogPublisherShared & Meta & SyslogJsonAuditLogPublisherResponseAllOf;


