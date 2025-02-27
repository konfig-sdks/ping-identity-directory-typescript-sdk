/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumfileBasedJsonHttpOperationLogPublisherSchemaUrn } from './enumfile-based-json-http-operation-log-publisher-schema-urn';
import { EnumlogPublisherCompressionMechanismProp } from './enumlog-publisher-compression-mechanism-prop';
import { EnumlogPublisherLogRequestHeadersProp } from './enumlog-publisher-log-request-headers-prop';
import { EnumlogPublisherLogRequestParametersProp } from './enumlog-publisher-log-request-parameters-prop';
import { EnumlogPublisherLogResponseHeadersProp } from './enumlog-publisher-log-response-headers-prop';
import { EnumlogPublisherLoggingErrorBehaviorProp } from './enumlog-publisher-logging-error-behavior-prop';

/**
 * 
 * @export
 * @interface FileBasedJsonHttpOperationLogPublisherShared
 */
export interface FileBasedJsonHttpOperationLogPublisherShared {
    /**
     * A description for this Log Publisher
     * @type {string}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumfileBasedJsonHttpOperationLogPublisherSchemaUrn>}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'schemas': Array<EnumfileBasedJsonHttpOperationLogPublisherSchemaUrn>;
    /**
     * The file name to use for the log files generated by the File Based JSON HTTP Operation Log Publisher. The path to the file can be specified either as relative to the server root or as an absolute path.
     * @type {string}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'logFile': string;
    /**
     * The UNIX permissions of the log files created by this File Based JSON HTTP Operation Log Publisher.
     * @type {string}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'logFilePermissions'?: string;
    /**
     * The rotation policy to use for the File Based JSON HTTP Operation Log Publisher .
     * @type {Array<string>}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'rotationPolicy'?: Array<string>;
    /**
     * A listener that should be notified whenever a log file is rotated out of service.
     * @type {Array<string>}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'rotationListener'?: Array<string>;
    /**
     * The retention policy to use for the File Based JSON HTTP Operation Log Publisher .
     * @type {Array<string>}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'retentionPolicy'?: Array<string>;
    /**
     * Specifies the type of compression (if any) to use for log files that are written.
     * @type {EnumlogPublisherCompressionMechanismProp}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'compressionMechanism'?: EnumlogPublisherCompressionMechanismProp;
    /**
     * Indicates whether the log should be cryptographically signed so that the log content cannot be altered in an undetectable manner.
     * @type {boolean}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'signLog'?: boolean;
    /**
     * Indicates whether log files should be encrypted so that their content is not available to unauthorized users.
     * @type {boolean}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'encryptLog'?: boolean;
    /**
     * Specifies the ID of the encryption settings definition that should be used to encrypt the data. If this is not provided, the server\'s preferred encryption settings definition will be used. The \"encryption-settings list\" command can be used to obtain a list of the encryption settings definitions available in the server.
     * @type {string}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'encryptionSettingsDefinitionID'?: string;
    /**
     * Specifies whether to append to existing log files.
     * @type {boolean}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'append'?: boolean;
    /**
     * Indicates whether the File Based JSON HTTP Operation Log Publisher will publish records asynchronously.
     * @type {boolean}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'asynchronous'?: boolean;
    /**
     * Specifies whether to flush the writer after every log record.
     * @type {boolean}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'autoFlush'?: boolean;
    /**
     * Specifies the log file buffer size.
     * @type {string}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'bufferSize'?: string;
    /**
     * The maximum number of log records that can be stored in the asynchronous queue.
     * @type {number}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'queueSize'?: number;
    /**
     * Specifies the interval at which to check whether the log files need to be rotated.
     * @type {string}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'timeInterval'?: string;
    /**
     * Indicates whether to record a log message with information about requests received from the client.
     * @type {boolean}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'logRequests'?: boolean;
    /**
     * Indicates whether to record a log message with information about the result of processing a requested HTTP operation.
     * @type {boolean}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'logResults'?: boolean;
    /**
     * Indicates whether log messages should include the product name for the Directory Server.
     * @type {boolean}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'includeProductName'?: boolean;
    /**
     * Indicates whether log messages should include the instance name for the Directory Server.
     * @type {boolean}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'includeInstanceName'?: boolean;
    /**
     * Indicates whether log messages should include the startup ID for the Directory Server, which is a value assigned to the server instance at startup and may be used to identify when the server has been restarted.
     * @type {boolean}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'includeStartupID'?: boolean;
    /**
     * Indicates whether log messages should include the thread ID for the Directory Server in each log message. This ID can be used to correlate log messages from the same thread within a single log as well as generated by the same thread across different types of log files. More information about the thread with a specific ID can be obtained using the cn=JVM Stack Trace,cn=monitor entry.
     * @type {boolean}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'includeThreadID'?: boolean;
    /**
     * Indicates whether result log messages should include all of the elements of request log messages. This may be used to record a single message per operation with details about both the request and response.
     * @type {boolean}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'includeRequestDetailsInResultMessages'?: boolean;
    /**
     * Indicates whether request log messages should include information about HTTP headers included in the request.
     * @type {EnumlogPublisherLogRequestHeadersProp}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'logRequestHeaders'?: EnumlogPublisherLogRequestHeadersProp;
    /**
     * Specifies the case-insensitive names of request headers that should be omitted from log messages (e.g., for the purpose of brevity or security). This will only be used if the log-request-headers property has a value of true.
     * @type {Array<string>}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'suppressedRequestHeaderName'?: Array<string>;
    /**
     * Indicates whether response log messages should include information about HTTP headers included in the response.
     * @type {EnumlogPublisherLogResponseHeadersProp}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'logResponseHeaders'?: EnumlogPublisherLogResponseHeadersProp;
    /**
     * Specifies the case-insensitive names of response headers that should be omitted from log messages (e.g., for the purpose of brevity or security). This will only be used if the log-response-headers property has a value of true.
     * @type {Array<string>}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'suppressedResponseHeaderName'?: Array<string>;
    /**
     * Indicates whether to log the type of credentials given if an \"Authorization\" header was included in the request. Logging the authorization type may be useful, and is much more secure than logging the entire value of the \"Authorization\" header.
     * @type {boolean}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'logRequestAuthorizationType'?: boolean;
    /**
     * Indicates whether to log the names of any cookies included in an HTTP request. Logging cookie names may be useful and is much more secure than logging the entire content of the cookies (which may include sensitive information).
     * @type {boolean}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'logRequestCookieNames'?: boolean;
    /**
     * Indicates whether to log the names of any cookies set in an HTTP response. Logging cookie names may be useful and is much more secure than logging the entire content of the cookies (which may include sensitive information).
     * @type {boolean}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'logResponseCookieNames'?: boolean;
    /**
     * Indicates what (if any) information about request parameters should be included in request log messages. Note that this will only be used for requests with a method other than GET, since GET request parameters will be included in the request URL.
     * @type {EnumlogPublisherLogRequestParametersProp}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'logRequestParameters'?: EnumlogPublisherLogRequestParametersProp;
    /**
     * Specifies the case-insensitive names of request parameters that should be omitted from log messages (e.g., for the purpose of brevity or security). This will only be used if the log-request-parameters property has a value of parameter-names or parameter-names-and-values.
     * @type {Array<string>}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'suppressedRequestParameterName'?: Array<string>;
    /**
     * Indicates whether request log messages should include information about the HTTP version specified in the request.
     * @type {boolean}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'logRequestProtocol'?: boolean;
    /**
     * Indicates whether the redirect URI (i.e., the value of the \"Location\" header from responses) should be included in response log messages.
     * @type {boolean}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'logRedirectURI'?: boolean;
    /**
     * Indicates whether the JSON objects should use a multi-line representation (with each object field and array value on its own line) that may be easier for administrators to read, but each message will be larger (because of additional spaces and end-of-line markers), and it may be more difficult to consume and parse through some text-oriented tools.
     * @type {boolean}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'writeMultiLineMessages'?: boolean;
    /**
     * Indicates whether the Log Publisher is enabled for use.
     * @type {boolean}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'enabled': boolean;
    /**
     * Specifies the behavior that the server should exhibit if an error occurs during logging processing.
     * @type {EnumlogPublisherLoggingErrorBehaviorProp}
     * @memberof FileBasedJsonHttpOperationLogPublisherShared
     */
    'loggingErrorBehavior'?: EnumlogPublisherLoggingErrorBehaviorProp;
}

