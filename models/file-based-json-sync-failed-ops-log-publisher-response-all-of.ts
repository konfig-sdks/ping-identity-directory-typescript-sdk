/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumfileBasedJsonSyncFailedOpsLogPublisherSchemaUrn } from './enumfile-based-json-sync-failed-ops-log-publisher-schema-urn';
import { EnumlogPublisherCompressionMechanismProp } from './enumlog-publisher-compression-mechanism-prop';
import { EnumlogPublisherLoggingErrorBehaviorProp } from './enumlog-publisher-logging-error-behavior-prop';

/**
 * 
 * @export
 * @interface FileBasedJsonSyncFailedOpsLogPublisherResponseAllOf
 */
export interface FileBasedJsonSyncFailedOpsLogPublisherResponseAllOf {
    /**
     * A description for this Log Publisher
     * @type {string}
     * @memberof FileBasedJsonSyncFailedOpsLogPublisherResponseAllOf
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumfileBasedJsonSyncFailedOpsLogPublisherSchemaUrn>}
     * @memberof FileBasedJsonSyncFailedOpsLogPublisherResponseAllOf
     */
    'schemas'?: Array<EnumfileBasedJsonSyncFailedOpsLogPublisherSchemaUrn>;
    /**
     * Name of the Log Publisher
     * @type {string}
     * @memberof FileBasedJsonSyncFailedOpsLogPublisherResponseAllOf
     */
    'id'?: string;
    /**
     * The file name to use for the log files generated by the File Based JSON Sync Failed Ops Log Publisher. The path to the file can be specified either as relative to the server root or as an absolute path.
     * @type {string}
     * @memberof FileBasedJsonSyncFailedOpsLogPublisherResponseAllOf
     */
    'logFile'?: string;
    /**
     * The UNIX permissions of the log files created by this File Based JSON Sync Failed Ops Log Publisher.
     * @type {string}
     * @memberof FileBasedJsonSyncFailedOpsLogPublisherResponseAllOf
     */
    'logFilePermissions'?: string;
    /**
     * The rotation policy to use for the File Based JSON Sync Failed Ops Log Publisher .
     * @type {Array<string>}
     * @memberof FileBasedJsonSyncFailedOpsLogPublisherResponseAllOf
     */
    'rotationPolicy'?: Array<string>;
    /**
     * A listener that should be notified whenever a log file is rotated out of service.
     * @type {Array<string>}
     * @memberof FileBasedJsonSyncFailedOpsLogPublisherResponseAllOf
     */
    'rotationListener'?: Array<string>;
    /**
     * The retention policy to use for the File Based JSON Sync Failed Ops Log Publisher .
     * @type {Array<string>}
     * @memberof FileBasedJsonSyncFailedOpsLogPublisherResponseAllOf
     */
    'retentionPolicy'?: Array<string>;
    /**
     * Specifies the type of compression (if any) to use for log files that are written.
     * @type {EnumlogPublisherCompressionMechanismProp}
     * @memberof FileBasedJsonSyncFailedOpsLogPublisherResponseAllOf
     */
    'compressionMechanism'?: EnumlogPublisherCompressionMechanismProp;
    /**
     * Indicates whether the log should be cryptographically signed so that the log content cannot be altered in an undetectable manner.
     * @type {boolean}
     * @memberof FileBasedJsonSyncFailedOpsLogPublisherResponseAllOf
     */
    'signLog'?: boolean;
    /**
     * Indicates whether log files should be encrypted so that their content is not available to unauthorized users.
     * @type {boolean}
     * @memberof FileBasedJsonSyncFailedOpsLogPublisherResponseAllOf
     */
    'encryptLog'?: boolean;
    /**
     * Specifies the ID of the encryption settings definition that should be used to encrypt the data. If this is not provided, the server\'s preferred encryption settings definition will be used. The \"encryption-settings list\" command can be used to obtain a list of the encryption settings definitions available in the server.
     * @type {string}
     * @memberof FileBasedJsonSyncFailedOpsLogPublisherResponseAllOf
     */
    'encryptionSettingsDefinitionID'?: string;
    /**
     * Specifies whether to append to existing log files.
     * @type {boolean}
     * @memberof FileBasedJsonSyncFailedOpsLogPublisherResponseAllOf
     */
    'append'?: boolean;
    /**
     * Indicates whether the File Based JSON Sync Failed Ops Log Publisher will publish records asynchronously.
     * @type {boolean}
     * @memberof FileBasedJsonSyncFailedOpsLogPublisherResponseAllOf
     */
    'asynchronous'?: boolean;
    /**
     * Specifies whether to flush the writer after every log record.
     * @type {boolean}
     * @memberof FileBasedJsonSyncFailedOpsLogPublisherResponseAllOf
     */
    'autoFlush'?: boolean;
    /**
     * Specifies the log file buffer size.
     * @type {string}
     * @memberof FileBasedJsonSyncFailedOpsLogPublisherResponseAllOf
     */
    'bufferSize'?: string;
    /**
     * The maximum number of log records that can be stored in the asynchronous queue.
     * @type {number}
     * @memberof FileBasedJsonSyncFailedOpsLogPublisherResponseAllOf
     */
    'queueSize'?: number;
    /**
     * Specifies the interval at which to check whether the log files need to be rotated.
     * @type {string}
     * @memberof FileBasedJsonSyncFailedOpsLogPublisherResponseAllOf
     */
    'timeInterval'?: string;
    /**
     * Indicates whether the JSON objects should use a multi-line representation (with each object field and array value on its own line) that may be easier for administrators to read, but each message will be larger (because of additional spaces and end-of-line markers), and it may be more difficult to consume and parse through some text-oriented tools.
     * @type {boolean}
     * @memberof FileBasedJsonSyncFailedOpsLogPublisherResponseAllOf
     */
    'writeMultiLineMessages'?: boolean;
    /**
     * Indicates whether log messages should include the product name for the Directory Server.
     * @type {boolean}
     * @memberof FileBasedJsonSyncFailedOpsLogPublisherResponseAllOf
     */
    'includeProductName'?: boolean;
    /**
     * Indicates whether log messages should include the instance name for the Directory Server.
     * @type {boolean}
     * @memberof FileBasedJsonSyncFailedOpsLogPublisherResponseAllOf
     */
    'includeInstanceName'?: boolean;
    /**
     * Indicates whether log messages should include the startup ID for the Directory Server, which is a value assigned to the server instance at startup and may be used to identify when the server has been restarted.
     * @type {boolean}
     * @memberof FileBasedJsonSyncFailedOpsLogPublisherResponseAllOf
     */
    'includeStartupID'?: boolean;
    /**
     * Indicates whether log messages should include the thread ID for the Directory Server in each log message. This ID can be used to correlate log messages from the same thread within a single log as well as generated by the same thread across different types of log files. More information about the thread with a specific ID can be obtained using the cn=JVM Stack Trace,cn=monitor entry.
     * @type {boolean}
     * @memberof FileBasedJsonSyncFailedOpsLogPublisherResponseAllOf
     */
    'includeThreadID'?: boolean;
    /**
     * Specifies which Sync Pipes can log messages to this Sync Log Publisher.
     * @type {Array<string>}
     * @memberof FileBasedJsonSyncFailedOpsLogPublisherResponseAllOf
     */
    'includeSyncPipe'?: Array<string>;
    /**
     * Indicates whether the Log Publisher is enabled for use.
     * @type {boolean}
     * @memberof FileBasedJsonSyncFailedOpsLogPublisherResponseAllOf
     */
    'enabled'?: boolean;
    /**
     * Specifies the behavior that the server should exhibit if an error occurs during logging processing.
     * @type {EnumlogPublisherLoggingErrorBehaviorProp}
     * @memberof FileBasedJsonSyncFailedOpsLogPublisherResponseAllOf
     */
    'loggingErrorBehavior'?: EnumlogPublisherLoggingErrorBehaviorProp;
}

