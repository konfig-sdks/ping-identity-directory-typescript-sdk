/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumfileBasedJsonAuditLogPublisherSchemaUrn } from './enumfile-based-json-audit-log-publisher-schema-urn';
import { EnumlogPublisherCompressionMechanismProp } from './enumlog-publisher-compression-mechanism-prop';
import { EnumlogPublisherFileBasedJsonAuditSoftDeleteEntryAuditBehaviorProp } from './enumlog-publisher-file-based-json-audit-soft-delete-entry-audit-behavior-prop';
import { EnumlogPublisherLoggingErrorBehaviorProp } from './enumlog-publisher-logging-error-behavior-prop';
import { FileBasedJsonAuditLogPublisherShared } from './file-based-json-audit-log-publisher-shared';
import { Meta } from './meta';
import { MetaMeta } from './meta-meta';
import { MetaUrnPingidentitySchemasConfigurationMessages20 } from './meta-urn-pingidentity-schemas-configuration-messages20';
import { SyslogJsonAuditLogPublisherResponseAllOf } from './syslog-json-audit-log-publisher-response-all-of';

/**
 * @type FileBasedJsonAuditLogPublisherResponse
 * @export
 */
export type FileBasedJsonAuditLogPublisherResponse = FileBasedJsonAuditLogPublisherShared & Meta & SyslogJsonAuditLogPublisherResponseAllOf;


