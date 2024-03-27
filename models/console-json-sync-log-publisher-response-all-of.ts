/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumconsoleJsonSyncLogPublisherSchemaUrn } from './enumconsole-json-sync-log-publisher-schema-urn';
import { EnumlogPublisherLoggedMessageTypeProp } from './enumlog-publisher-logged-message-type-prop';
import { EnumlogPublisherLoggingErrorBehaviorProp } from './enumlog-publisher-logging-error-behavior-prop';
import { EnumlogPublisherOutputLocationProp } from './enumlog-publisher-output-location-prop';

/**
 * 
 * @export
 * @interface ConsoleJsonSyncLogPublisherResponseAllOf
 */
export interface ConsoleJsonSyncLogPublisherResponseAllOf {
    /**
     * A description for this Log Publisher
     * @type {string}
     * @memberof ConsoleJsonSyncLogPublisherResponseAllOf
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumconsoleJsonSyncLogPublisherSchemaUrn>}
     * @memberof ConsoleJsonSyncLogPublisherResponseAllOf
     */
    'schemas'?: Array<EnumconsoleJsonSyncLogPublisherSchemaUrn>;
    /**
     * Name of the Log Publisher
     * @type {string}
     * @memberof ConsoleJsonSyncLogPublisherResponseAllOf
     */
    'id'?: string;
    /**
     * Indicates whether the Console JSON Sync Log Publisher is enabled for use.
     * @type {boolean}
     * @memberof ConsoleJsonSyncLogPublisherResponseAllOf
     */
    'enabled'?: boolean;
    /**
     * Specifies the output stream to which JSON-formatted error log messages should be written.
     * @type {EnumlogPublisherOutputLocationProp}
     * @memberof ConsoleJsonSyncLogPublisherResponseAllOf
     */
    'outputLocation'?: EnumlogPublisherOutputLocationProp;
    /**
     * Indicates whether the JSON objects should use a multi-line representation (with each object field and array value on its own line) that may be easier for administrators to read, but each message will be larger (because of additional spaces and end-of-line markers), and it may be more difficult to consume and parse through some text-oriented tools.
     * @type {boolean}
     * @memberof ConsoleJsonSyncLogPublisherResponseAllOf
     */
    'writeMultiLineMessages'?: boolean;
    /**
     * Indicates whether log messages should include the product name for the Directory Server.
     * @type {boolean}
     * @memberof ConsoleJsonSyncLogPublisherResponseAllOf
     */
    'includeProductName'?: boolean;
    /**
     * Indicates whether log messages should include the instance name for the Directory Server.
     * @type {boolean}
     * @memberof ConsoleJsonSyncLogPublisherResponseAllOf
     */
    'includeInstanceName'?: boolean;
    /**
     * Indicates whether log messages should include the startup ID for the Directory Server, which is a value assigned to the server instance at startup and may be used to identify when the server has been restarted.
     * @type {boolean}
     * @memberof ConsoleJsonSyncLogPublisherResponseAllOf
     */
    'includeStartupID'?: boolean;
    /**
     * Indicates whether log messages should include the thread ID for the Directory Server in each log message. This ID can be used to correlate log messages from the same thread within a single log as well as generated by the same thread across different types of log files. More information about the thread with a specific ID can be obtained using the cn=JVM Stack Trace,cn=monitor entry.
     * @type {boolean}
     * @memberof ConsoleJsonSyncLogPublisherResponseAllOf
     */
    'includeThreadID'?: boolean;
    /**
     * Specifies which Sync Pipes can log messages to this Sync Log Publisher.
     * @type {Array<string>}
     * @memberof ConsoleJsonSyncLogPublisherResponseAllOf
     */
    'includeSyncPipe'?: Array<string>;
    /**
     * 
     * @type {Array<EnumlogPublisherLoggedMessageTypeProp>}
     * @memberof ConsoleJsonSyncLogPublisherResponseAllOf
     */
    'loggedMessageType'?: Array<EnumlogPublisherLoggedMessageTypeProp>;
    /**
     * Specifies the behavior that the server should exhibit if an error occurs during logging processing.
     * @type {EnumlogPublisherLoggingErrorBehaviorProp}
     * @memberof ConsoleJsonSyncLogPublisherResponseAllOf
     */
    'loggingErrorBehavior'?: EnumlogPublisherLoggingErrorBehaviorProp;
}

