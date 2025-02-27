/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumgroovyScriptedFileBasedErrorLogPublisherSchemaUrn } from './enumgroovy-scripted-file-based-error-log-publisher-schema-urn';
import { EnumlogPublisherCompressionMechanismProp } from './enumlog-publisher-compression-mechanism-prop';
import { EnumlogPublisherDefaultSeverityProp } from './enumlog-publisher-default-severity-prop';
import { EnumlogPublisherLoggingErrorBehaviorProp } from './enumlog-publisher-logging-error-behavior-prop';

/**
 * 
 * @export
 * @interface GroovyScriptedFileBasedErrorLogPublisherShared
 */
export interface GroovyScriptedFileBasedErrorLogPublisherShared {
    /**
     * A description for this Log Publisher
     * @type {string}
     * @memberof GroovyScriptedFileBasedErrorLogPublisherShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumgroovyScriptedFileBasedErrorLogPublisherSchemaUrn>}
     * @memberof GroovyScriptedFileBasedErrorLogPublisherShared
     */
    'schemas': Array<EnumgroovyScriptedFileBasedErrorLogPublisherSchemaUrn>;
    /**
     * The fully-qualified name of the Groovy class providing the logic for the Groovy Scripted File Based Error Log Publisher.
     * @type {string}
     * @memberof GroovyScriptedFileBasedErrorLogPublisherShared
     */
    'scriptClass': string;
    /**
     * The file name to use for the log files generated by the Scripted File Based Error Log Publisher. The path to the file can be specified either as relative to the server root or as an absolute path.
     * @type {string}
     * @memberof GroovyScriptedFileBasedErrorLogPublisherShared
     */
    'logFile': string;
    /**
     * The UNIX permissions of the log files created by this Scripted File Based Error Log Publisher.
     * @type {string}
     * @memberof GroovyScriptedFileBasedErrorLogPublisherShared
     */
    'logFilePermissions'?: string;
    /**
     * The rotation policy to use for the Scripted File Based Error Log Publisher .
     * @type {Array<string>}
     * @memberof GroovyScriptedFileBasedErrorLogPublisherShared
     */
    'rotationPolicy'?: Array<string>;
    /**
     * A listener that should be notified whenever a log file is rotated out of service.
     * @type {Array<string>}
     * @memberof GroovyScriptedFileBasedErrorLogPublisherShared
     */
    'rotationListener'?: Array<string>;
    /**
     * The retention policy to use for the Scripted File Based Error Log Publisher .
     * @type {Array<string>}
     * @memberof GroovyScriptedFileBasedErrorLogPublisherShared
     */
    'retentionPolicy'?: Array<string>;
    /**
     * Specifies the type of compression (if any) to use for log files that are written.
     * @type {EnumlogPublisherCompressionMechanismProp}
     * @memberof GroovyScriptedFileBasedErrorLogPublisherShared
     */
    'compressionMechanism'?: EnumlogPublisherCompressionMechanismProp;
    /**
     * Indicates whether the log should be cryptographically signed so that the log content cannot be altered in an undetectable manner.
     * @type {boolean}
     * @memberof GroovyScriptedFileBasedErrorLogPublisherShared
     */
    'signLog'?: boolean;
    /**
     * Indicates whether log files should be encrypted so that their content is not available to unauthorized users.
     * @type {boolean}
     * @memberof GroovyScriptedFileBasedErrorLogPublisherShared
     */
    'encryptLog'?: boolean;
    /**
     * Specifies the ID of the encryption settings definition that should be used to encrypt the data. If this is not provided, the server\'s preferred encryption settings definition will be used. The \"encryption-settings list\" command can be used to obtain a list of the encryption settings definitions available in the server.
     * @type {string}
     * @memberof GroovyScriptedFileBasedErrorLogPublisherShared
     */
    'encryptionSettingsDefinitionID'?: string;
    /**
     * Specifies whether to append to existing log files.
     * @type {boolean}
     * @memberof GroovyScriptedFileBasedErrorLogPublisherShared
     */
    'append'?: boolean;
    /**
     * The set of arguments used to customize the behavior for the Scripted File Based Error Log Publisher. Each configuration property should be given in the form \'name=value\'.
     * @type {Array<string>}
     * @memberof GroovyScriptedFileBasedErrorLogPublisherShared
     */
    'scriptArgument'?: Array<string>;
    /**
     * Indicates whether the Scripted File Based Error Log Publisher will publish records asynchronously.
     * @type {boolean}
     * @memberof GroovyScriptedFileBasedErrorLogPublisherShared
     */
    'asynchronous'?: boolean;
    /**
     * Specifies whether to flush the writer after every log record.
     * @type {boolean}
     * @memberof GroovyScriptedFileBasedErrorLogPublisherShared
     */
    'autoFlush'?: boolean;
    /**
     * Specifies the log file buffer size.
     * @type {string}
     * @memberof GroovyScriptedFileBasedErrorLogPublisherShared
     */
    'bufferSize'?: string;
    /**
     * The maximum number of log records that can be stored in the asynchronous queue.
     * @type {number}
     * @memberof GroovyScriptedFileBasedErrorLogPublisherShared
     */
    'queueSize'?: number;
    /**
     * Specifies the interval at which to check whether the log files need to be rotated.
     * @type {string}
     * @memberof GroovyScriptedFileBasedErrorLogPublisherShared
     */
    'timeInterval'?: string;
    /**
     * 
     * @type {Array<EnumlogPublisherDefaultSeverityProp>}
     * @memberof GroovyScriptedFileBasedErrorLogPublisherShared
     */
    'defaultSeverity'?: Array<EnumlogPublisherDefaultSeverityProp>;
    /**
     * Specifies the override severity levels for the logger based on the category of the messages.
     * @type {Array<string>}
     * @memberof GroovyScriptedFileBasedErrorLogPublisherShared
     */
    'overrideSeverity'?: Array<string>;
    /**
     * Indicates whether the Log Publisher is enabled for use.
     * @type {boolean}
     * @memberof GroovyScriptedFileBasedErrorLogPublisherShared
     */
    'enabled': boolean;
    /**
     * Specifies the behavior that the server should exhibit if an error occurs during logging processing.
     * @type {EnumlogPublisherLoggingErrorBehaviorProp}
     * @memberof GroovyScriptedFileBasedErrorLogPublisherShared
     */
    'loggingErrorBehavior'?: EnumlogPublisherLoggingErrorBehaviorProp;
}

