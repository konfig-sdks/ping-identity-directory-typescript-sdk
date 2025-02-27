/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumlogPublisherCompressionMechanismProp } from './enumlog-publisher-compression-mechanism-prop';
import { EnumlogPublisherDefaultSeverityProp } from './enumlog-publisher-default-severity-prop';
import { EnumlogPublisherLoggingErrorBehaviorProp } from './enumlog-publisher-logging-error-behavior-prop';
import { EnumthirdPartyFileBasedErrorLogPublisherSchemaUrn } from './enumthird-party-file-based-error-log-publisher-schema-urn';

/**
 * 
 * @export
 * @interface ThirdPartyFileBasedErrorLogPublisherShared
 */
export interface ThirdPartyFileBasedErrorLogPublisherShared {
    /**
     * A description for this Log Publisher
     * @type {string}
     * @memberof ThirdPartyFileBasedErrorLogPublisherShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumthirdPartyFileBasedErrorLogPublisherSchemaUrn>}
     * @memberof ThirdPartyFileBasedErrorLogPublisherShared
     */
    'schemas': Array<EnumthirdPartyFileBasedErrorLogPublisherSchemaUrn>;
    /**
     * The file name to use for the log files generated by the Third Party File Based Error Log Publisher. The path to the file can be specified either as relative to the server root or as an absolute path.
     * @type {string}
     * @memberof ThirdPartyFileBasedErrorLogPublisherShared
     */
    'logFile': string;
    /**
     * The UNIX permissions of the log files created by this Third Party File Based Error Log Publisher.
     * @type {string}
     * @memberof ThirdPartyFileBasedErrorLogPublisherShared
     */
    'logFilePermissions'?: string;
    /**
     * The rotation policy to use for the Third Party File Based Error Log Publisher .
     * @type {Array<string>}
     * @memberof ThirdPartyFileBasedErrorLogPublisherShared
     */
    'rotationPolicy'?: Array<string>;
    /**
     * A listener that should be notified whenever a log file is rotated out of service.
     * @type {Array<string>}
     * @memberof ThirdPartyFileBasedErrorLogPublisherShared
     */
    'rotationListener'?: Array<string>;
    /**
     * The retention policy to use for the Third Party File Based Error Log Publisher .
     * @type {Array<string>}
     * @memberof ThirdPartyFileBasedErrorLogPublisherShared
     */
    'retentionPolicy'?: Array<string>;
    /**
     * Specifies the type of compression (if any) to use for log files that are written.
     * @type {EnumlogPublisherCompressionMechanismProp}
     * @memberof ThirdPartyFileBasedErrorLogPublisherShared
     */
    'compressionMechanism'?: EnumlogPublisherCompressionMechanismProp;
    /**
     * Indicates whether the log should be cryptographically signed so that the log content cannot be altered in an undetectable manner.
     * @type {boolean}
     * @memberof ThirdPartyFileBasedErrorLogPublisherShared
     */
    'signLog'?: boolean;
    /**
     * Indicates whether log files should be encrypted so that their content is not available to unauthorized users.
     * @type {boolean}
     * @memberof ThirdPartyFileBasedErrorLogPublisherShared
     */
    'encryptLog'?: boolean;
    /**
     * Specifies the ID of the encryption settings definition that should be used to encrypt the data. If this is not provided, the server\'s preferred encryption settings definition will be used. The \"encryption-settings list\" command can be used to obtain a list of the encryption settings definitions available in the server.
     * @type {string}
     * @memberof ThirdPartyFileBasedErrorLogPublisherShared
     */
    'encryptionSettingsDefinitionID'?: string;
    /**
     * Specifies whether to append to existing log files.
     * @type {boolean}
     * @memberof ThirdPartyFileBasedErrorLogPublisherShared
     */
    'append'?: boolean;
    /**
     * The fully-qualified name of the Java class providing the logic for the Third Party File Based Error Log Publisher.
     * @type {string}
     * @memberof ThirdPartyFileBasedErrorLogPublisherShared
     */
    'extensionClass': string;
    /**
     * The set of arguments used to customize the behavior for the Third Party File Based Error Log Publisher. Each configuration property should be given in the form \'name=value\'.
     * @type {Array<string>}
     * @memberof ThirdPartyFileBasedErrorLogPublisherShared
     */
    'extensionArgument'?: Array<string>;
    /**
     * Indicates whether the Third Party File Based Error Log Publisher will publish records asynchronously.
     * @type {boolean}
     * @memberof ThirdPartyFileBasedErrorLogPublisherShared
     */
    'asynchronous'?: boolean;
    /**
     * Specifies whether to flush the writer after every log record.
     * @type {boolean}
     * @memberof ThirdPartyFileBasedErrorLogPublisherShared
     */
    'autoFlush'?: boolean;
    /**
     * Specifies the log file buffer size.
     * @type {string}
     * @memberof ThirdPartyFileBasedErrorLogPublisherShared
     */
    'bufferSize'?: string;
    /**
     * The maximum number of log records that can be stored in the asynchronous queue.
     * @type {number}
     * @memberof ThirdPartyFileBasedErrorLogPublisherShared
     */
    'queueSize'?: number;
    /**
     * Specifies the interval at which to check whether the log files need to be rotated.
     * @type {string}
     * @memberof ThirdPartyFileBasedErrorLogPublisherShared
     */
    'timeInterval'?: string;
    /**
     * 
     * @type {Array<EnumlogPublisherDefaultSeverityProp>}
     * @memberof ThirdPartyFileBasedErrorLogPublisherShared
     */
    'defaultSeverity'?: Array<EnumlogPublisherDefaultSeverityProp>;
    /**
     * Specifies the override severity levels for the logger based on the category of the messages.
     * @type {Array<string>}
     * @memberof ThirdPartyFileBasedErrorLogPublisherShared
     */
    'overrideSeverity'?: Array<string>;
    /**
     * Indicates whether the Log Publisher is enabled for use.
     * @type {boolean}
     * @memberof ThirdPartyFileBasedErrorLogPublisherShared
     */
    'enabled': boolean;
    /**
     * Specifies the behavior that the server should exhibit if an error occurs during logging processing.
     * @type {EnumlogPublisherLoggingErrorBehaviorProp}
     * @memberof ThirdPartyFileBasedErrorLogPublisherShared
     */
    'loggingErrorBehavior'?: EnumlogPublisherLoggingErrorBehaviorProp;
}

