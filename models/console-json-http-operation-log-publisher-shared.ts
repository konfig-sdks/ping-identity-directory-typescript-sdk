/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumconsoleJsonHttpOperationLogPublisherSchemaUrn } from './enumconsole-json-http-operation-log-publisher-schema-urn';
import { EnumlogPublisherLogRequestHeadersProp } from './enumlog-publisher-log-request-headers-prop';
import { EnumlogPublisherLogRequestParametersProp } from './enumlog-publisher-log-request-parameters-prop';
import { EnumlogPublisherLogResponseHeadersProp } from './enumlog-publisher-log-response-headers-prop';
import { EnumlogPublisherLoggingErrorBehaviorProp } from './enumlog-publisher-logging-error-behavior-prop';
import { EnumlogPublisherOutputLocationProp } from './enumlog-publisher-output-location-prop';

/**
 * 
 * @export
 * @interface ConsoleJsonHttpOperationLogPublisherShared
 */
export interface ConsoleJsonHttpOperationLogPublisherShared {
    /**
     * A description for this Log Publisher
     * @type {string}
     * @memberof ConsoleJsonHttpOperationLogPublisherShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumconsoleJsonHttpOperationLogPublisherSchemaUrn>}
     * @memberof ConsoleJsonHttpOperationLogPublisherShared
     */
    'schemas': Array<EnumconsoleJsonHttpOperationLogPublisherSchemaUrn>;
    /**
     * Indicates whether the Console JSON HTTP Operation Log Publisher is enabled for use.
     * @type {boolean}
     * @memberof ConsoleJsonHttpOperationLogPublisherShared
     */
    'enabled': boolean;
    /**
     * Specifies the output stream to which JSON-formatted error log messages should be written.
     * @type {EnumlogPublisherOutputLocationProp}
     * @memberof ConsoleJsonHttpOperationLogPublisherShared
     */
    'outputLocation'?: EnumlogPublisherOutputLocationProp;
    /**
     * Indicates whether to record a log message with information about requests received from the client.
     * @type {boolean}
     * @memberof ConsoleJsonHttpOperationLogPublisherShared
     */
    'logRequests'?: boolean;
    /**
     * Indicates whether to record a log message with information about the result of processing a requested HTTP operation.
     * @type {boolean}
     * @memberof ConsoleJsonHttpOperationLogPublisherShared
     */
    'logResults'?: boolean;
    /**
     * Indicates whether log messages should include the product name for the Directory Server.
     * @type {boolean}
     * @memberof ConsoleJsonHttpOperationLogPublisherShared
     */
    'includeProductName'?: boolean;
    /**
     * Indicates whether log messages should include the instance name for the Directory Server.
     * @type {boolean}
     * @memberof ConsoleJsonHttpOperationLogPublisherShared
     */
    'includeInstanceName'?: boolean;
    /**
     * Indicates whether log messages should include the startup ID for the Directory Server, which is a value assigned to the server instance at startup and may be used to identify when the server has been restarted.
     * @type {boolean}
     * @memberof ConsoleJsonHttpOperationLogPublisherShared
     */
    'includeStartupID'?: boolean;
    /**
     * Indicates whether log messages should include the thread ID for the Directory Server in each log message. This ID can be used to correlate log messages from the same thread within a single log as well as generated by the same thread across different types of log files. More information about the thread with a specific ID can be obtained using the cn=JVM Stack Trace,cn=monitor entry.
     * @type {boolean}
     * @memberof ConsoleJsonHttpOperationLogPublisherShared
     */
    'includeThreadID'?: boolean;
    /**
     * Indicates whether result log messages should include all of the elements of request log messages. This may be used to record a single message per operation with details about both the request and response.
     * @type {boolean}
     * @memberof ConsoleJsonHttpOperationLogPublisherShared
     */
    'includeRequestDetailsInResultMessages'?: boolean;
    /**
     * Indicates whether request log messages should include information about HTTP headers included in the request.
     * @type {EnumlogPublisherLogRequestHeadersProp}
     * @memberof ConsoleJsonHttpOperationLogPublisherShared
     */
    'logRequestHeaders'?: EnumlogPublisherLogRequestHeadersProp;
    /**
     * Specifies the case-insensitive names of request headers that should be omitted from log messages (e.g., for the purpose of brevity or security). This will only be used if the log-request-headers property has a value of true.
     * @type {Array<string>}
     * @memberof ConsoleJsonHttpOperationLogPublisherShared
     */
    'suppressedRequestHeaderName'?: Array<string>;
    /**
     * Indicates whether response log messages should include information about HTTP headers included in the response.
     * @type {EnumlogPublisherLogResponseHeadersProp}
     * @memberof ConsoleJsonHttpOperationLogPublisherShared
     */
    'logResponseHeaders'?: EnumlogPublisherLogResponseHeadersProp;
    /**
     * Specifies the case-insensitive names of response headers that should be omitted from log messages (e.g., for the purpose of brevity or security). This will only be used if the log-response-headers property has a value of true.
     * @type {Array<string>}
     * @memberof ConsoleJsonHttpOperationLogPublisherShared
     */
    'suppressedResponseHeaderName'?: Array<string>;
    /**
     * Indicates whether to log the type of credentials given if an \"Authorization\" header was included in the request. Logging the authorization type may be useful, and is much more secure than logging the entire value of the \"Authorization\" header.
     * @type {boolean}
     * @memberof ConsoleJsonHttpOperationLogPublisherShared
     */
    'logRequestAuthorizationType'?: boolean;
    /**
     * Indicates whether to log the names of any cookies included in an HTTP request. Logging cookie names may be useful and is much more secure than logging the entire content of the cookies (which may include sensitive information).
     * @type {boolean}
     * @memberof ConsoleJsonHttpOperationLogPublisherShared
     */
    'logRequestCookieNames'?: boolean;
    /**
     * Indicates whether to log the names of any cookies set in an HTTP response. Logging cookie names may be useful and is much more secure than logging the entire content of the cookies (which may include sensitive information).
     * @type {boolean}
     * @memberof ConsoleJsonHttpOperationLogPublisherShared
     */
    'logResponseCookieNames'?: boolean;
    /**
     * Indicates what (if any) information about request parameters should be included in request log messages. Note that this will only be used for requests with a method other than GET, since GET request parameters will be included in the request URL.
     * @type {EnumlogPublisherLogRequestParametersProp}
     * @memberof ConsoleJsonHttpOperationLogPublisherShared
     */
    'logRequestParameters'?: EnumlogPublisherLogRequestParametersProp;
    /**
     * Specifies the case-insensitive names of request parameters that should be omitted from log messages (e.g., for the purpose of brevity or security). This will only be used if the log-request-parameters property has a value of parameter-names or parameter-names-and-values.
     * @type {Array<string>}
     * @memberof ConsoleJsonHttpOperationLogPublisherShared
     */
    'suppressedRequestParameterName'?: Array<string>;
    /**
     * Indicates whether request log messages should include information about the HTTP version specified in the request.
     * @type {boolean}
     * @memberof ConsoleJsonHttpOperationLogPublisherShared
     */
    'logRequestProtocol'?: boolean;
    /**
     * Indicates whether the redirect URI (i.e., the value of the \"Location\" header from responses) should be included in response log messages.
     * @type {boolean}
     * @memberof ConsoleJsonHttpOperationLogPublisherShared
     */
    'logRedirectURI'?: boolean;
    /**
     * Indicates whether the JSON objects should use a multi-line representation (with each object field and array value on its own line) that may be easier for administrators to read, but each message will be larger (because of additional spaces and end-of-line markers), and it may be more difficult to consume and parse through some text-oriented tools.
     * @type {boolean}
     * @memberof ConsoleJsonHttpOperationLogPublisherShared
     */
    'writeMultiLineMessages'?: boolean;
    /**
     * Specifies the behavior that the server should exhibit if an error occurs during logging processing.
     * @type {EnumlogPublisherLoggingErrorBehaviorProp}
     * @memberof ConsoleJsonHttpOperationLogPublisherShared
     */
    'loggingErrorBehavior'?: EnumlogPublisherLoggingErrorBehaviorProp;
}

