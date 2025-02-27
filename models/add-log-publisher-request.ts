/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { AddAdminAlertAccessLogPublisherRequest } from './add-admin-alert-access-log-publisher-request';
import { AddCommonLogFileHttpOperationLogPublisherRequest } from './add-common-log-file-http-operation-log-publisher-request';
import { AddConsoleJsonAuditLogPublisherRequest } from './add-console-json-audit-log-publisher-request';
import { AddConsoleJsonHttpOperationLogPublisherRequest } from './add-console-json-http-operation-log-publisher-request';
import { AddDebugAccessLogPublisherRequest } from './add-debug-access-log-publisher-request';
import { AddDetailedHttpOperationLogPublisherRequest } from './add-detailed-http-operation-log-publisher-request';
import { AddFileBasedAccessLogPublisherRequest } from './add-file-based-access-log-publisher-request';
import { AddFileBasedAuditLogPublisherRequest } from './add-file-based-audit-log-publisher-request';
import { AddFileBasedDebugLogPublisherRequest } from './add-file-based-debug-log-publisher-request';
import { AddFileBasedErrorLogPublisherRequest } from './add-file-based-error-log-publisher-request';
import { AddFileBasedJsonAuditLogPublisherRequest } from './add-file-based-json-audit-log-publisher-request';
import { AddFileBasedJsonHttpOperationLogPublisherRequest } from './add-file-based-json-http-operation-log-publisher-request';
import { AddFileBasedTraceLogPublisherRequest } from './add-file-based-trace-log-publisher-request';
import { AddGroovyScriptedAccessLogPublisherRequest } from './add-groovy-scripted-access-log-publisher-request';
import { AddGroovyScriptedErrorLogPublisherRequest } from './add-groovy-scripted-error-log-publisher-request';
import { AddGroovyScriptedFileBasedAccessLogPublisherRequest } from './add-groovy-scripted-file-based-access-log-publisher-request';
import { AddGroovyScriptedFileBasedErrorLogPublisherRequest } from './add-groovy-scripted-file-based-error-log-publisher-request';
import { AddGroovyScriptedHttpOperationLogPublisherRequest } from './add-groovy-scripted-http-operation-log-publisher-request';
import { AddJdbcBasedAccessLogPublisherRequest } from './add-jdbc-based-access-log-publisher-request';
import { AddJdbcBasedErrorLogPublisherRequest } from './add-jdbc-based-error-log-publisher-request';
import { AddJsonAccessLogPublisherRequest } from './add-json-access-log-publisher-request';
import { AddJsonErrorLogPublisherRequest } from './add-json-error-log-publisher-request';
import { AddOperationTimingAccessLogPublisherRequest } from './add-operation-timing-access-log-publisher-request';
import { AddSyslogBasedAccessLogPublisherRequest } from './add-syslog-based-access-log-publisher-request';
import { AddSyslogBasedErrorLogPublisherRequest } from './add-syslog-based-error-log-publisher-request';
import { AddSyslogJsonAccessLogPublisherRequest } from './add-syslog-json-access-log-publisher-request';
import { AddSyslogJsonAuditLogPublisherRequest } from './add-syslog-json-audit-log-publisher-request';
import { AddSyslogJsonErrorLogPublisherRequest } from './add-syslog-json-error-log-publisher-request';
import { AddSyslogJsonHttpOperationLogPublisherRequest } from './add-syslog-json-http-operation-log-publisher-request';
import { AddSyslogTextAccessLogPublisherRequest } from './add-syslog-text-access-log-publisher-request';
import { AddSyslogTextErrorLogPublisherRequest } from './add-syslog-text-error-log-publisher-request';
import { AddThirdPartyAccessLogPublisherRequest } from './add-third-party-access-log-publisher-request';
import { AddThirdPartyErrorLogPublisherRequest } from './add-third-party-error-log-publisher-request';
import { AddThirdPartyFileBasedAccessLogPublisherRequest } from './add-third-party-file-based-access-log-publisher-request';
import { AddThirdPartyFileBasedErrorLogPublisherRequest } from './add-third-party-file-based-error-log-publisher-request';
import { AddThirdPartyHttpOperationLogPublisherRequest } from './add-third-party-http-operation-log-publisher-request';
import { EnumgroovyScriptedHttpOperationLogPublisherSchemaUrn } from './enumgroovy-scripted-http-operation-log-publisher-schema-urn';
import { EnumlogPublisherAccessTokenValidatorMessageTypeProp } from './enumlog-publisher-access-token-validator-message-type-prop';
import { EnumlogPublisherCompressionMechanismProp } from './enumlog-publisher-compression-mechanism-prop';
import { EnumlogPublisherConsentMessageTypeProp } from './enumlog-publisher-consent-message-type-prop';
import { EnumlogPublisherConsoleJsonAuditSoftDeleteEntryAuditBehaviorProp } from './enumlog-publisher-console-json-audit-soft-delete-entry-audit-behavior-prop';
import { EnumlogPublisherDebugMessageTypeProp } from './enumlog-publisher-debug-message-type-prop';
import { EnumlogPublisherDefaultDebugCategoryProp } from './enumlog-publisher-default-debug-category-prop';
import { EnumlogPublisherDefaultDebugLevelProp } from './enumlog-publisher-default-debug-level-prop';
import { EnumlogPublisherDefaultSeverityProp } from './enumlog-publisher-default-severity-prop';
import { EnumlogPublisherDirectoryRESTAPIMessageTypeProp } from './enumlog-publisher-directory-restapimessage-type-prop';
import { EnumlogPublisherExtensionMessageTypeProp } from './enumlog-publisher-extension-message-type-prop';
import { EnumlogPublisherHttpMessageTypeProp } from './enumlog-publisher-http-message-type-prop';
import { EnumlogPublisherIdTokenValidatorMessageTypeProp } from './enumlog-publisher-id-token-validator-message-type-prop';
import { EnumlogPublisherLogRequestHeadersProp } from './enumlog-publisher-log-request-headers-prop';
import { EnumlogPublisherLogRequestParametersProp } from './enumlog-publisher-log-request-parameters-prop';
import { EnumlogPublisherLogResponseHeadersProp } from './enumlog-publisher-log-response-headers-prop';
import { EnumlogPublisherLoggingErrorBehaviorProp } from './enumlog-publisher-logging-error-behavior-prop';
import { EnumlogPublisherOutputLocationProp } from './enumlog-publisher-output-location-prop';
import { EnumlogPublisherScimMessageTypeProp } from './enumlog-publisher-scim-message-type-prop';
import { EnumlogPublisherSyslogFacilityProp } from './enumlog-publisher-syslog-facility-prop';
import { EnumlogPublisherSyslogSeverityProp } from './enumlog-publisher-syslog-severity-prop';
import { EnumlogPublisherTimestampPrecisionProp } from './enumlog-publisher-timestamp-precision-prop';

/**
 * @type AddLogPublisherRequest
 * @export
 */
export type AddLogPublisherRequest = AddAdminAlertAccessLogPublisherRequest | AddCommonLogFileHttpOperationLogPublisherRequest | AddConsoleJsonAuditLogPublisherRequest | AddConsoleJsonHttpOperationLogPublisherRequest | AddDebugAccessLogPublisherRequest | AddDetailedHttpOperationLogPublisherRequest | AddFileBasedAccessLogPublisherRequest | AddFileBasedAuditLogPublisherRequest | AddFileBasedDebugLogPublisherRequest | AddFileBasedErrorLogPublisherRequest | AddFileBasedJsonAuditLogPublisherRequest | AddFileBasedJsonHttpOperationLogPublisherRequest | AddFileBasedTraceLogPublisherRequest | AddGroovyScriptedAccessLogPublisherRequest | AddGroovyScriptedErrorLogPublisherRequest | AddGroovyScriptedFileBasedAccessLogPublisherRequest | AddGroovyScriptedFileBasedErrorLogPublisherRequest | AddGroovyScriptedHttpOperationLogPublisherRequest | AddJdbcBasedAccessLogPublisherRequest | AddJdbcBasedErrorLogPublisherRequest | AddJsonAccessLogPublisherRequest | AddJsonErrorLogPublisherRequest | AddOperationTimingAccessLogPublisherRequest | AddSyslogBasedAccessLogPublisherRequest | AddSyslogBasedErrorLogPublisherRequest | AddSyslogJsonAccessLogPublisherRequest | AddSyslogJsonAuditLogPublisherRequest | AddSyslogJsonErrorLogPublisherRequest | AddSyslogJsonHttpOperationLogPublisherRequest | AddSyslogTextAccessLogPublisherRequest | AddSyslogTextErrorLogPublisherRequest | AddThirdPartyAccessLogPublisherRequest | AddThirdPartyErrorLogPublisherRequest | AddThirdPartyFileBasedAccessLogPublisherRequest | AddThirdPartyFileBasedErrorLogPublisherRequest | AddThirdPartyHttpOperationLogPublisherRequest;


