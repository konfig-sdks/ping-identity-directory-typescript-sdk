/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumlogPublisherLoggingErrorBehaviorProp } from './enumlog-publisher-logging-error-behavior-prop';
import { EnumthirdPartyAccessLogPublisherSchemaUrn } from './enumthird-party-access-log-publisher-schema-urn';

/**
 * 
 * @export
 * @interface ThirdPartyAccessLogPublisherShared
 */
export interface ThirdPartyAccessLogPublisherShared {
    /**
     * A description for this Log Publisher
     * @type {string}
     * @memberof ThirdPartyAccessLogPublisherShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumthirdPartyAccessLogPublisherSchemaUrn>}
     * @memberof ThirdPartyAccessLogPublisherShared
     */
    'schemas': Array<EnumthirdPartyAccessLogPublisherSchemaUrn>;
    /**
     * The fully-qualified name of the Java class providing the logic for the Third Party Access Log Publisher.
     * @type {string}
     * @memberof ThirdPartyAccessLogPublisherShared
     */
    'extensionClass': string;
    /**
     * The set of arguments used to customize the behavior for the Third Party Access Log Publisher. Each configuration property should be given in the form \'name=value\'.
     * @type {Array<string>}
     * @memberof ThirdPartyAccessLogPublisherShared
     */
    'extensionArgument'?: Array<string>;
    /**
     * Indicates whether to log information about connections established to the server.
     * @type {boolean}
     * @memberof ThirdPartyAccessLogPublisherShared
     */
    'logConnects'?: boolean;
    /**
     * Indicates whether to log information about connections that have been closed by the client or terminated by the server.
     * @type {boolean}
     * @memberof ThirdPartyAccessLogPublisherShared
     */
    'logDisconnects'?: boolean;
    /**
     * Indicates whether to log information about the result of any security negotiation (e.g., SSL handshake) processing that has been performed.
     * @type {boolean}
     * @memberof ThirdPartyAccessLogPublisherShared
     */
    'logSecurityNegotiation'?: boolean;
    /**
     * Indicates whether to log information about any client certificates presented to the server.
     * @type {boolean}
     * @memberof ThirdPartyAccessLogPublisherShared
     */
    'logClientCertificates'?: boolean;
    /**
     * Indicates whether to log information about requests received from clients.
     * @type {boolean}
     * @memberof ThirdPartyAccessLogPublisherShared
     */
    'logRequests'?: boolean;
    /**
     * Indicates whether to log information about the results of client requests.
     * @type {boolean}
     * @memberof ThirdPartyAccessLogPublisherShared
     */
    'logResults'?: boolean;
    /**
     * Indicates whether to log information about search result entries sent to the client.
     * @type {boolean}
     * @memberof ThirdPartyAccessLogPublisherShared
     */
    'logSearchEntries'?: boolean;
    /**
     * Indicates whether to log information about search result references sent to the client.
     * @type {boolean}
     * @memberof ThirdPartyAccessLogPublisherShared
     */
    'logSearchReferences'?: boolean;
    /**
     * Indicates whether to log information about intermediate responses sent to the client.
     * @type {boolean}
     * @memberof ThirdPartyAccessLogPublisherShared
     */
    'logIntermediateResponses'?: boolean;
    /**
     * Indicates whether internal operations (for example, operations that are initiated by plugins) should be logged along with the operations that are requested by users.
     * @type {boolean}
     * @memberof ThirdPartyAccessLogPublisherShared
     */
    'suppressInternalOperations'?: boolean;
    /**
     * Indicates whether access messages that are generated by replication operations should be suppressed.
     * @type {boolean}
     * @memberof ThirdPartyAccessLogPublisherShared
     */
    'suppressReplicationOperations'?: boolean;
    /**
     * Indicates whether to automatically log result messages for any operation in which the corresponding request was logged. In such cases, the result, entry, and reference criteria will be ignored, although the log-responses, log-search-entries, and log-search-references properties will be honored.
     * @type {boolean}
     * @memberof ThirdPartyAccessLogPublisherShared
     */
    'correlateRequestsAndResults'?: boolean;
    /**
     * Specifies a set of connection criteria that must match the associated client connection in order for a connect, disconnect, request, or result message to be logged.
     * @type {string}
     * @memberof ThirdPartyAccessLogPublisherShared
     */
    'connectionCriteria'?: string;
    /**
     * Specifies a set of request criteria that must match the associated operation request in order for a request or result to be logged by this Access Log Publisher.
     * @type {string}
     * @memberof ThirdPartyAccessLogPublisherShared
     */
    'requestCriteria'?: string;
    /**
     * Specifies a set of result criteria that must match the associated operation result in order for that result to be logged by this Access Log Publisher.
     * @type {string}
     * @memberof ThirdPartyAccessLogPublisherShared
     */
    'resultCriteria'?: string;
    /**
     * Specifies a set of search entry criteria that must match the associated search result entry in order for that it to be logged by this Access Log Publisher.
     * @type {string}
     * @memberof ThirdPartyAccessLogPublisherShared
     */
    'searchEntryCriteria'?: string;
    /**
     * Specifies a set of search reference criteria that must match the associated search result reference in order for that it to be logged by this Access Log Publisher.
     * @type {string}
     * @memberof ThirdPartyAccessLogPublisherShared
     */
    'searchReferenceCriteria'?: string;
    /**
     * Indicates whether the Log Publisher is enabled for use.
     * @type {boolean}
     * @memberof ThirdPartyAccessLogPublisherShared
     */
    'enabled': boolean;
    /**
     * Specifies the behavior that the server should exhibit if an error occurs during logging processing.
     * @type {EnumlogPublisherLoggingErrorBehaviorProp}
     * @memberof ThirdPartyAccessLogPublisherShared
     */
    'loggingErrorBehavior'?: EnumlogPublisherLoggingErrorBehaviorProp;
}

