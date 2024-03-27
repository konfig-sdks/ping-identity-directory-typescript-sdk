/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumreplicationDomainMissingChangesPolicyProp } from './enumreplication-domain-missing-changes-policy-prop';
import { EnumreplicationDomainSchemaUrn } from './enumreplication-domain-schema-urn';

/**
 * 
 * @export
 * @interface ReplicationDomainResponseAllOf
 */
export interface ReplicationDomainResponseAllOf {
    /**
     * 
     * @type {Array<EnumreplicationDomainSchemaUrn>}
     * @memberof ReplicationDomainResponseAllOf
     */
    'schemas'?: Array<EnumreplicationDomainSchemaUrn>;
    /**
     * Name of the Replication Domain
     * @type {string}
     * @memberof ReplicationDomainResponseAllOf
     */
    'id'?: string;
    /**
     * Specifies a unique identifier for the Directory Server within the Replication Domain.
     * @type {number}
     * @memberof ReplicationDomainResponseAllOf
     */
    'serverID'?: number;
    /**
     * Specifies the base DN of the replicated data.
     * @type {string}
     * @memberof ReplicationDomainResponseAllOf
     */
    'baseDN'?: string;
    /**
     * Specifies the maximum number of replication updates the Directory Server can have outstanding from the Replication Server.
     * @type {number}
     * @memberof ReplicationDomainResponseAllOf
     */
    'windowSize'?: number;
    /**
     * Specifies the heartbeat interval that the Directory Server will use when communicating with Replication Servers.
     * @type {string}
     * @memberof ReplicationDomainResponseAllOf
     */
    'heartbeatInterval'?: string;
    /**
     * The time in seconds after which historical information used in replication conflict resolution is purged. The information is removed from entries when they are modified after the purge delay has elapsed.
     * @type {string}
     * @memberof ReplicationDomainResponseAllOf
     */
    'syncHistPurgeDelay'?: string;
    /**
     * When set to true, changes are only replicated with server instances that belong to the same replication set.
     * @type {boolean}
     * @memberof ReplicationDomainResponseAllOf
     */
    'restricted'?: boolean;
    /**
     * Defines the maximum time to retry a failed operation. An operation will be retried only if it appears that the failure might be dependent on an earlier operation from a different server that hasn\'t replicated yet. The frequency of the retry is determined by the dependent-ops-replay-failure-wait-time property.
     * @type {string}
     * @memberof ReplicationDomainResponseAllOf
     */
    'onReplayFailureWaitForDependentOpsTimeout'?: string;
    /**
     * Defines how long to wait before retrying certain operations, specifically operations that might have failed because they depend on an operation from a different server that has not yet replicated to this instance.
     * @type {string}
     * @memberof ReplicationDomainResponseAllOf
     */
    'dependentOpsReplayFailureWaitTime'?: string;
    /**
     * Determines how the server responds when replication detects that some changes might have been missed. Each missing changes policy is a set of missing changes actions to take for a set of missing changes types. The value configured here only applies to this particular replication domain.
     * @type {EnumreplicationDomainMissingChangesPolicyProp}
     * @memberof ReplicationDomainResponseAllOf
     */
    'missingChangesPolicy'?: EnumreplicationDomainMissingChangesPolicyProp;
}

