/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumjsonErrorLogPublisherSchemaUrn } from './enumjson-error-log-publisher-schema-urn';
import { EnumlogPublisherCompressionMechanismProp } from './enumlog-publisher-compression-mechanism-prop';
import { EnumlogPublisherDefaultSeverityProp } from './enumlog-publisher-default-severity-prop';
import { EnumlogPublisherLoggingErrorBehaviorProp } from './enumlog-publisher-logging-error-behavior-prop';

/**
 * 
 * @export
 * @interface JsonErrorLogPublisherShared
 */
export interface JsonErrorLogPublisherShared {
    /**
     * A description for this Log Publisher
     * @type {string}
     * @memberof JsonErrorLogPublisherShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumjsonErrorLogPublisherSchemaUrn>}
     * @memberof JsonErrorLogPublisherShared
     */
    'schemas': Array<EnumjsonErrorLogPublisherSchemaUrn>;
    /**
     * The file name to use for the log files generated by the JSON Error Log Publisher. The path to the file can be specified either as relative to the server root or as an absolute path.
     * @type {string}
     * @memberof JsonErrorLogPublisherShared
     */
    'logFile': string;
    /**
     * The UNIX permissions of the log files created by this JSON Error Log Publisher.
     * @type {string}
     * @memberof JsonErrorLogPublisherShared
     */
    'logFilePermissions'?: string;
    /**
     * The rotation policy to use for the JSON Error Log Publisher .
     * @type {Array<string>}
     * @memberof JsonErrorLogPublisherShared
     */
    'rotationPolicy'?: Array<string>;
    /**
     * A listener that should be notified whenever a log file is rotated out of service.
     * @type {Array<string>}
     * @memberof JsonErrorLogPublisherShared
     */
    'rotationListener'?: Array<string>;
    /**
     * The retention policy to use for the JSON Error Log Publisher .
     * @type {Array<string>}
     * @memberof JsonErrorLogPublisherShared
     */
    'retentionPolicy'?: Array<string>;
    /**
     * Specifies the type of compression (if any) to use for log files that are written.
     * @type {EnumlogPublisherCompressionMechanismProp}
     * @memberof JsonErrorLogPublisherShared
     */
    'compressionMechanism'?: EnumlogPublisherCompressionMechanismProp;
    /**
     * Indicates whether the log should be cryptographically signed so that the log content cannot be altered in an undetectable manner.
     * @type {boolean}
     * @memberof JsonErrorLogPublisherShared
     */
    'signLog'?: boolean;
    /**
     * Indicates whether log files should be encrypted so that their content is not available to unauthorized users.
     * @type {boolean}
     * @memberof JsonErrorLogPublisherShared
     */
    'encryptLog'?: boolean;
    /**
     * Specifies the ID of the encryption settings definition that should be used to encrypt the data. If this is not provided, the server\'s preferred encryption settings definition will be used. The \"encryption-settings list\" command can be used to obtain a list of the encryption settings definitions available in the server.
     * @type {string}
     * @memberof JsonErrorLogPublisherShared
     */
    'encryptionSettingsDefinitionID'?: string;
    /**
     * Specifies whether to append to existing log files.
     * @type {boolean}
     * @memberof JsonErrorLogPublisherShared
     */
    'append'?: boolean;
    /**
     * Indicates whether the JSON Error Log Publisher will publish records asynchronously.
     * @type {boolean}
     * @memberof JsonErrorLogPublisherShared
     */
    'asynchronous'?: boolean;
    /**
     * Specifies whether to flush the writer after every log record.
     * @type {boolean}
     * @memberof JsonErrorLogPublisherShared
     */
    'autoFlush'?: boolean;
    /**
     * Specifies the log file buffer size.
     * @type {string}
     * @memberof JsonErrorLogPublisherShared
     */
    'bufferSize'?: string;
    /**
     * The maximum number of log records that can be stored in the asynchronous queue.
     * @type {number}
     * @memberof JsonErrorLogPublisherShared
     */
    'queueSize'?: number;
    /**
     * Specifies the interval at which to check whether the log files need to be rotated.
     * @type {string}
     * @memberof JsonErrorLogPublisherShared
     */
    'timeInterval'?: string;
    /**
     * Indicates whether the JSON objects should be formatted to span multiple lines with a single element on each line. The multi-line format is potentially more user friendly (if administrators may need to look at the log files), but each message will be larger because of the additional spaces and end-of-line markers.
     * @type {boolean}
     * @memberof JsonErrorLogPublisherShared
     */
    'writeMultiLineMessages'?: boolean;
    /**
     * Indicates whether log messages should include the product name for the Directory Server.
     * @type {boolean}
     * @memberof JsonErrorLogPublisherShared
     */
    'includeProductName'?: boolean;
    /**
     * Indicates whether log messages should include the instance name for the Directory Server.
     * @type {boolean}
     * @memberof JsonErrorLogPublisherShared
     */
    'includeInstanceName'?: boolean;
    /**
     * Indicates whether log messages should include the startup ID for the Directory Server, which is a value assigned to the server instance at startup and may be used to identify when the server has been restarted.
     * @type {boolean}
     * @memberof JsonErrorLogPublisherShared
     */
    'includeStartupID'?: boolean;
    /**
     * Indicates whether log messages should include the thread ID for the Directory Server in each log message. This ID can be used to correlate log messages from the same thread within a single log as well as generated by the same thread across different types of log files. More information about the thread with a specific ID can be obtained using the cn=JVM Stack Trace,cn=monitor entry.
     * @type {boolean}
     * @memberof JsonErrorLogPublisherShared
     */
    'includeThreadID'?: boolean;
    /**
     * Indicates whether to use the generified version of the log message string (which may use placeholders like %s for a string or %d for an integer), rather than the version of the message with those placeholders replaced with specific values that would normally be written to the log.
     * @type {boolean}
     * @memberof JsonErrorLogPublisherShared
     */
    'generifyMessageStringsWhenPossible'?: boolean;
    /**
     * 
     * @type {Array<EnumlogPublisherDefaultSeverityProp>}
     * @memberof JsonErrorLogPublisherShared
     */
    'defaultSeverity'?: Array<EnumlogPublisherDefaultSeverityProp>;
    /**
     * Specifies the override severity levels for the logger based on the category of the messages.
     * @type {Array<string>}
     * @memberof JsonErrorLogPublisherShared
     */
    'overrideSeverity'?: Array<string>;
    /**
     * Indicates whether the Log Publisher is enabled for use.
     * @type {boolean}
     * @memberof JsonErrorLogPublisherShared
     */
    'enabled': boolean;
    /**
     * Specifies the behavior that the server should exhibit if an error occurs during logging processing.
     * @type {EnumlogPublisherLoggingErrorBehaviorProp}
     * @memberof JsonErrorLogPublisherShared
     */
    'loggingErrorBehavior'?: EnumlogPublisherLoggingErrorBehaviorProp;
}

