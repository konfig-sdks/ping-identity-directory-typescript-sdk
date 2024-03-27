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

/**
 * 
 * @export
 * @interface FileBasedDebugLogPublisherShared
 */
export interface FileBasedDebugLogPublisherShared {
    /**
     * A description for this Log Publisher
     * @type {string}
     * @memberof FileBasedDebugLogPublisherShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumfileBasedDebugLogPublisherSchemaUrn>}
     * @memberof FileBasedDebugLogPublisherShared
     */
    'schemas': Array<EnumfileBasedDebugLogPublisherSchemaUrn>;
    /**
     * The file name to use for the log files generated by the File Based Debug Log Publisher. The path to the file can be specified either as relative to the server root or as an absolute path.
     * @type {string}
     * @memberof FileBasedDebugLogPublisherShared
     */
    'logFile': string;
    /**
     * The UNIX permissions of the log files created by this File Based Debug Log Publisher.
     * @type {string}
     * @memberof FileBasedDebugLogPublisherShared
     */
    'logFilePermissions'?: string;
    /**
     * The rotation policy to use for the File Based Debug Log Publisher .
     * @type {Array<string>}
     * @memberof FileBasedDebugLogPublisherShared
     */
    'rotationPolicy'?: Array<string>;
    /**
     * A listener that should be notified whenever a log file is rotated out of service.
     * @type {Array<string>}
     * @memberof FileBasedDebugLogPublisherShared
     */
    'rotationListener'?: Array<string>;
    /**
     * The retention policy to use for the File Based Debug Log Publisher .
     * @type {Array<string>}
     * @memberof FileBasedDebugLogPublisherShared
     */
    'retentionPolicy'?: Array<string>;
    /**
     * Specifies the type of compression (if any) to use for log files that are written.
     * @type {EnumlogPublisherCompressionMechanismProp}
     * @memberof FileBasedDebugLogPublisherShared
     */
    'compressionMechanism'?: EnumlogPublisherCompressionMechanismProp;
    /**
     * Indicates whether the log should be cryptographically signed so that the log content cannot be altered in an undetectable manner.
     * @type {boolean}
     * @memberof FileBasedDebugLogPublisherShared
     */
    'signLog'?: boolean;
    /**
     * Indicates whether log files should be encrypted so that their content is not available to unauthorized users.
     * @type {boolean}
     * @memberof FileBasedDebugLogPublisherShared
     */
    'encryptLog'?: boolean;
    /**
     * Specifies the ID of the encryption settings definition that should be used to encrypt the data. If this is not provided, the server\'s preferred encryption settings definition will be used. The \"encryption-settings list\" command can be used to obtain a list of the encryption settings definitions available in the server.
     * @type {string}
     * @memberof FileBasedDebugLogPublisherShared
     */
    'encryptionSettingsDefinitionID'?: string;
    /**
     * Specifies whether to append to existing log files.
     * @type {boolean}
     * @memberof FileBasedDebugLogPublisherShared
     */
    'append'?: boolean;
    /**
     * Indicates whether the File Based Debug Log Publisher will publish records asynchronously.
     * @type {boolean}
     * @memberof FileBasedDebugLogPublisherShared
     */
    'asynchronous'?: boolean;
    /**
     * Specifies whether to flush the writer after every log record.
     * @type {boolean}
     * @memberof FileBasedDebugLogPublisherShared
     */
    'autoFlush'?: boolean;
    /**
     * Specifies the log file buffer size.
     * @type {string}
     * @memberof FileBasedDebugLogPublisherShared
     */
    'bufferSize'?: string;
    /**
     * The maximum number of log records that can be stored in the asynchronous queue.
     * @type {number}
     * @memberof FileBasedDebugLogPublisherShared
     */
    'queueSize'?: number;
    /**
     * Specifies the interval at which to check whether the log files need to be rotated.
     * @type {string}
     * @memberof FileBasedDebugLogPublisherShared
     */
    'timeInterval'?: string;
    /**
     * Specifies the smallest time unit to be included in timestamps.
     * @type {EnumlogPublisherTimestampPrecisionProp}
     * @memberof FileBasedDebugLogPublisherShared
     */
    'timestampPrecision'?: EnumlogPublisherTimestampPrecisionProp;
    /**
     * The lowest severity level of debug messages to log when none of the defined targets match the message.
     * @type {EnumlogPublisherDefaultDebugLevelProp}
     * @memberof FileBasedDebugLogPublisherShared
     */
    'defaultDebugLevel'?: EnumlogPublisherDefaultDebugLevelProp;
    /**
     * 
     * @type {Array<EnumlogPublisherDefaultDebugCategoryProp>}
     * @memberof FileBasedDebugLogPublisherShared
     */
    'defaultDebugCategory'?: Array<EnumlogPublisherDefaultDebugCategoryProp>;
    /**
     * Indicates whether to include method arguments in debug messages logged by default.
     * @type {boolean}
     * @memberof FileBasedDebugLogPublisherShared
     */
    'defaultOmitMethodEntryArguments'?: boolean;
    /**
     * Indicates whether to include the return value in debug messages logged by default.
     * @type {boolean}
     * @memberof FileBasedDebugLogPublisherShared
     */
    'defaultOmitMethodReturnValue'?: boolean;
    /**
     * Indicates whether to include the cause of exceptions in exception thrown and caught messages logged by default.
     * @type {boolean}
     * @memberof FileBasedDebugLogPublisherShared
     */
    'defaultIncludeThrowableCause'?: boolean;
    /**
     * Indicates the number of stack frames to include in the stack trace for method entry and exception thrown messages.
     * @type {number}
     * @memberof FileBasedDebugLogPublisherShared
     */
    'defaultThrowableStackFrames'?: number;
    /**
     * Indicates whether the Log Publisher is enabled for use.
     * @type {boolean}
     * @memberof FileBasedDebugLogPublisherShared
     */
    'enabled': boolean;
    /**
     * Specifies the behavior that the server should exhibit if an error occurs during logging processing.
     * @type {EnumlogPublisherLoggingErrorBehaviorProp}
     * @memberof FileBasedDebugLogPublisherShared
     */
    'loggingErrorBehavior'?: EnumlogPublisherLoggingErrorBehaviorProp;
}

