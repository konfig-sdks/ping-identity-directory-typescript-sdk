/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumreplicationSynchronizationProviderSchemaUrn } from './enumreplication-synchronization-provider-schema-urn';

/**
 * 
 * @export
 * @interface ReplicationSynchronizationProviderResponseAllOf
 */
export interface ReplicationSynchronizationProviderResponseAllOf {
    /**
     * A description for this Synchronization Provider
     * @type {string}
     * @memberof ReplicationSynchronizationProviderResponseAllOf
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumreplicationSynchronizationProviderSchemaUrn>}
     * @memberof ReplicationSynchronizationProviderResponseAllOf
     */
    'schemas'?: Array<EnumreplicationSynchronizationProviderSchemaUrn>;
    /**
     * Name of the Synchronization Provider
     * @type {string}
     * @memberof ReplicationSynchronizationProviderResponseAllOf
     */
    'id'?: string;
    /**
     * Specifies the number of update replay threads.
     * @type {number}
     * @memberof ReplicationSynchronizationProviderResponseAllOf
     */
    'numUpdateReplayThreads'?: number;
    /**
     * Indicates whether the Synchronization Provider is enabled for use.
     * @type {boolean}
     * @memberof ReplicationSynchronizationProviderResponseAllOf
     */
    'enabled'?: boolean;
}

