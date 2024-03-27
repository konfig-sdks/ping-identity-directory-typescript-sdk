/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumclientConnectionPolicyAllowedAuthTypeProp } from './enumclient-connection-policy-allowed-auth-type-prop';
import { EnumclientConnectionPolicyAllowedFilterTypeProp } from './enumclient-connection-policy-allowed-filter-type-prop';
import { EnumclientConnectionPolicyAllowedOperationProp } from './enumclient-connection-policy-allowed-operation-prop';
import { EnumclientConnectionPolicyConnectionOperationRateExceededBehaviorProp } from './enumclient-connection-policy-connection-operation-rate-exceeded-behavior-prop';
import { EnumclientConnectionPolicyMaximumConcurrentOperationsPerConnectionExceededBehaviorProp } from './enumclient-connection-policy-maximum-concurrent-operations-per-connection-exceeded-behavior-prop';
import { EnumclientConnectionPolicyPolicyOperationRateExceededBehaviorProp } from './enumclient-connection-policy-policy-operation-rate-exceeded-behavior-prop';
import { EnumclientConnectionPolicySchemaUrn } from './enumclient-connection-policy-schema-urn';

/**
 * 
 * @export
 * @interface ClientConnectionPolicyShared
 */
export interface ClientConnectionPolicyShared {
    /**
     * A description for this Client Connection Policy
     * @type {string}
     * @memberof ClientConnectionPolicyShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumclientConnectionPolicySchemaUrn>}
     * @memberof ClientConnectionPolicyShared
     */
    'schemas'?: Array<EnumclientConnectionPolicySchemaUrn>;
    /**
     * Specifies a name which uniquely identifies this Client Connection Policy in the server.
     * @type {string}
     * @memberof ClientConnectionPolicyShared
     */
    'policyID': string;
    /**
     * Indicates whether this Client Connection Policy is enabled for use in the server. If a Client Connection Policy is disabled, then no new client connections will be associated with it.
     * @type {boolean}
     * @memberof ClientConnectionPolicyShared
     */
    'enabled': boolean;
    /**
     * Specifies the order in which Client Connection Policy definitions will be evaluated. A Client Connection Policy with a lower index will be evaluated before one with a higher index, and the first Client Connection Policy evaluated which may apply to a client connection will be used for that connection. Each Client Connection Policy must be assigned a unique evaluation order index value.
     * @type {number}
     * @memberof ClientConnectionPolicyShared
     */
    'evaluationOrderIndex': number;
    /**
     * Specifies a set of connection criteria that must match the associated client connection for it to be associated with this Client Connection Policy.
     * @type {string}
     * @memberof ClientConnectionPolicyShared
     */
    'connectionCriteria'?: string;
    /**
     * Indicates whether any client connection for which this Client Connection Policy is selected should be terminated. This makes it possible to define fine-grained criteria for clients that should not be allowed to connect to this Directory Server.
     * @type {boolean}
     * @memberof ClientConnectionPolicyShared
     */
    'terminateConnection'?: boolean;
    /**
     * Provides the ability to indicate that some attributes should be considered sensitive and additional protection should be in place when interacting with those attributes.
     * @type {Array<string>}
     * @memberof ClientConnectionPolicyShared
     */
    'sensitiveAttribute'?: Array<string>;
    /**
     * Specifies the set of global sensitive attribute definitions that should not apply to this client connection policy.
     * @type {Array<string>}
     * @memberof ClientConnectionPolicyShared
     */
    'excludeGlobalSensitiveAttribute'?: Array<string>;
    /**
     * Specifies the result code map that should be used for clients associated with this Client Connection Policy. If a value is defined for this property, then it will override any result code map referenced in the global configuration.
     * @type {string}
     * @memberof ClientConnectionPolicyShared
     */
    'resultCodeMap'?: string;
    /**
     * Specifies the set of backend base DNs for which subtree views should be included in this Client Connection Policy.
     * @type {Array<string>}
     * @memberof ClientConnectionPolicyShared
     */
    'includedBackendBaseDN'?: Array<string>;
    /**
     * Specifies the set of backend base DNs for which subtree views should be excluded from this Client Connection Policy.
     * @type {Array<string>}
     * @memberof ClientConnectionPolicyShared
     */
    'excludedBackendBaseDN'?: Array<string>;
    /**
     * 
     * @type {Array<EnumclientConnectionPolicyAllowedOperationProp>}
     * @memberof ClientConnectionPolicyShared
     */
    'allowedOperation'?: Array<EnumclientConnectionPolicyAllowedOperationProp>;
    /**
     * Specifies a request criteria object that will be required to match all requests submitted by clients associated with this Client Connection Policy. If a client submits a request that does not satisfy this request criteria object, then that request will be rejected.
     * @type {string}
     * @memberof ClientConnectionPolicyShared
     */
    'requiredOperationRequestCriteria'?: string;
    /**
     * Specifies a request criteria object that must not match any requests submitted by clients associated with this Client Connection Policy. If a client submits a request that satisfies this request criteria object, then that request will be rejected.
     * @type {string}
     * @memberof ClientConnectionPolicyShared
     */
    'prohibitedOperationRequestCriteria'?: string;
    /**
     * Specifies the OIDs of the controls that clients associated with this Client Connection Policy will be allowed to include in requests.
     * @type {Array<string>}
     * @memberof ClientConnectionPolicyShared
     */
    'allowedRequestControl'?: Array<string>;
    /**
     * Specifies the OIDs of the controls that clients associated with this Client Connection Policy will not be allowed to include in requests.
     * @type {Array<string>}
     * @memberof ClientConnectionPolicyShared
     */
    'deniedRequestControl'?: Array<string>;
    /**
     * Specifies the OIDs of the extended operations that clients associated with this Client Connection Policy will be allowed to request.
     * @type {Array<string>}
     * @memberof ClientConnectionPolicyShared
     */
    'allowedExtendedOperation'?: Array<string>;
    /**
     * Specifies the OIDs of the extended operations that clients associated with this Client Connection Policy will not be allowed to request.
     * @type {Array<string>}
     * @memberof ClientConnectionPolicyShared
     */
    'deniedExtendedOperation'?: Array<string>;
    /**
     * 
     * @type {Array<EnumclientConnectionPolicyAllowedAuthTypeProp>}
     * @memberof ClientConnectionPolicyShared
     */
    'allowedAuthType'?: Array<EnumclientConnectionPolicyAllowedAuthTypeProp>;
    /**
     * Specifies the names of the SASL mechanisms that clients associated with this Client Connection Policy will be allowed to request.
     * @type {Array<string>}
     * @memberof ClientConnectionPolicyShared
     */
    'allowedSASLMechanism'?: Array<string>;
    /**
     * Specifies the names of the SASL mechanisms that clients associated with this Client Connection Policy will not be allowed to request.
     * @type {Array<string>}
     * @memberof ClientConnectionPolicyShared
     */
    'deniedSASLMechanism'?: Array<string>;
    /**
     * 
     * @type {Array<EnumclientConnectionPolicyAllowedFilterTypeProp>}
     * @memberof ClientConnectionPolicyShared
     */
    'allowedFilterType'?: Array<EnumclientConnectionPolicyAllowedFilterTypeProp>;
    /**
     * Indicates whether clients will be allowed to request search operations that cannot be efficiently processed using the set of indexes defined in the corresponding backend. Note that even if this is false, some clients may be able to request unindexed searches if the allow-unindexed-searches-with-control property has a value of true and the necessary conditions are satisfied.
     * @type {boolean}
     * @memberof ClientConnectionPolicyShared
     */
    'allowUnindexedSearches'?: boolean;
    /**
     * Indicates whether clients will be allowed to request search operations that cannot be efficiently processed using the set of indexes defined in the corresponding backend, as long as the search request also includes the permit unindexed search request control and the requester has the unindexed-search-with-control privilege (or that privilege is disabled in the global configuration).
     * @type {boolean}
     * @memberof ClientConnectionPolicyShared
     */
    'allowUnindexedSearchesWithControl'?: boolean;
    /**
     * Specifies the minimum number of consecutive bytes that must be present in any subInitial, subAny, or subFinal element of a substring filter component (i.e., the minimum number of consecutive bytes between wildcard characters in a substring filter). Any attempt to use a substring search with an element containing fewer than this number of bytes will be rejected.
     * @type {number}
     * @memberof ClientConnectionPolicyShared
     */
    'minimumSubstringLength'?: number;
    /**
     * Specifies the maximum number of client connections which may be associated with this Client Connection Policy at any given time.
     * @type {number}
     * @memberof ClientConnectionPolicyShared
     */
    'maximumConcurrentConnections'?: number;
    /**
     * Specifies the maximum length of time that a connection associated with this Client Connection Policy may be established. Any connection which is associated with this Client Connection Policy and has been established for longer than this period of time may be terminated.
     * @type {string}
     * @memberof ClientConnectionPolicyShared
     */
    'maximumConnectionDuration'?: string;
    /**
     * Specifies the maximum length of time that a connection associated with this Client Connection Policy may remain established after the completion of the last operation processed on that connection. Any new operation requested on the connection will reset this timer. Any connection associated with this Client Connection Policy which has been idle for longer than this length of time may be terminated.
     * @type {string}
     * @memberof ClientConnectionPolicyShared
     */
    'maximumIdleConnectionDuration'?: string;
    /**
     * Specifies the maximum number of operations that may be requested by any client connection associated with this Client Connection Policy. If an attempt is made to process more than this number of operations on a client connection, then that connection will be terminated.
     * @type {number}
     * @memberof ClientConnectionPolicyShared
     */
    'maximumOperationCountPerConnection'?: number;
    /**
     * Specifies the maximum number of concurrent operations that can be in progress for any connection. This can help prevent a single client connection from monopolizing server processing resources by sending a large number of concurrent asynchronous requests. A value of zero indicates that no limit will be placed on the number of concurrent requests for a single client.
     * @type {number}
     * @memberof ClientConnectionPolicyShared
     */
    'maximumConcurrentOperationsPerConnection'?: number;
    /**
     * Specifies the maximum length of time that the server should wait for an outstanding operation to complete before rejecting a new request received when the maximum number of outstanding operations are already in progress on that connection. If an existing outstanding operation on the connection completes before this time, then the operation will be processed. Otherwise, the operation will be rejected with a \"busy\" result.
     * @type {string}
     * @memberof ClientConnectionPolicyShared
     */
    'maximumConcurrentOperationWaitTimeBeforeRejecting'?: string;
    /**
     * Specifies the behavior that the Directory Server should exhibit if a client attempts to invoke more concurrent operations on a single connection than allowed by the maximum-concurrent-operations-per-connection property.
     * @type {EnumclientConnectionPolicyMaximumConcurrentOperationsPerConnectionExceededBehaviorProp}
     * @memberof ClientConnectionPolicyShared
     */
    'maximumConcurrentOperationsPerConnectionExceededBehavior'?: EnumclientConnectionPolicyMaximumConcurrentOperationsPerConnectionExceededBehaviorProp;
    /**
     * Specifies the maximum rate at which a client associated with this Client Connection Policy may issue requests to the Directory Server. If any client attempts to request operations at a rate higher than this limit, then the server will exhibit the behavior described in the connection-operation-rate-exceeded-behavior property.
     * @type {Array<string>}
     * @memberof ClientConnectionPolicyShared
     */
    'maximumConnectionOperationRate'?: Array<string>;
    /**
     * Specifies the behavior that the Directory Server should exhibit if a client connection attempts to exceed a rate defined in the maximum-connection-operation-rate property. If the configured behavior is one that will reject requested operations, then that behavior will persist until the end of the corresponding interval. The server will resume allowing that client to perform operations when that interval expires, as long as no other operation rate limits have been exceeded.
     * @type {EnumclientConnectionPolicyConnectionOperationRateExceededBehaviorProp}
     * @memberof ClientConnectionPolicyShared
     */
    'connectionOperationRateExceededBehavior'?: EnumclientConnectionPolicyConnectionOperationRateExceededBehaviorProp;
    /**
     * Specifies the maximum rate at which all clients associated with this Client Connection Policy, as a collective set, may issue requests to the Directory Server. If this limit is exceeded, then the server will exhibit the behavior described in the policy-operation-rate-exceeded-behavior property.
     * @type {Array<string>}
     * @memberof ClientConnectionPolicyShared
     */
    'maximumPolicyOperationRate'?: Array<string>;
    /**
     * Specifies the behavior that the Directory Server should exhibit if a client connection attempts to exceed a rate defined in the maximum-policy-operation-rate property. If the configured behavior is one that will reject requested operations, then that behavior will persist until the end of the corresponding interval. The server will resume allowing clients associated with this Client Connection Policy to perform operations when that interval expires, as long as no other operation rate limits have been exceeded.
     * @type {EnumclientConnectionPolicyPolicyOperationRateExceededBehaviorProp}
     * @memberof ClientConnectionPolicyShared
     */
    'policyOperationRateExceededBehavior'?: EnumclientConnectionPolicyPolicyOperationRateExceededBehaviorProp;
    /**
     * Specifies the maximum number of entries that may be returned for a search performed by a client associated with this Client Connection Policy.
     * @type {number}
     * @memberof ClientConnectionPolicyShared
     */
    'maximumSearchSizeLimit'?: number;
    /**
     * Specifies the maximum length of time that the server should spend processing search operations requested by clients associated with this Client Connection Policy.
     * @type {string}
     * @memberof ClientConnectionPolicyShared
     */
    'maximumSearchTimeLimit'?: string;
    /**
     * Specifies the maximum number of entries that may be examined by a backend in the course of processing a search requested by clients associated with this Client Connection Policy.
     * @type {number}
     * @memberof ClientConnectionPolicyShared
     */
    'maximumSearchLookthroughLimit'?: number;
    /**
     * Specifies the maximum number of entries that may be joined with any single search result entry for a search request performed by a client associated with this Client Connection Policy.
     * @type {number}
     * @memberof ClientConnectionPolicyShared
     */
    'maximumLDAPJoinSizeLimit'?: number;
    /**
     * Specifies the maximum number of entries that the server will attempt to sort without the benefit of a VLV index. A value of zero indicates that no limit should be enforced.
     * @type {number}
     * @memberof ClientConnectionPolicyShared
     */
    'maximumSortSizeLimitWithoutVLVIndex'?: number;
}

