/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumentryCacheMonitorProviderSchemaUrn } from './enumentry-cache-monitor-provider-schema-urn';

/**
 * 
 * @export
 * @interface EntryCacheMonitorProviderResponseAllOf
 */
export interface EntryCacheMonitorProviderResponseAllOf {
    /**
     * A description for this Monitor Provider
     * @type {string}
     * @memberof EntryCacheMonitorProviderResponseAllOf
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumentryCacheMonitorProviderSchemaUrn>}
     * @memberof EntryCacheMonitorProviderResponseAllOf
     */
    'schemas'?: Array<EnumentryCacheMonitorProviderSchemaUrn>;
    /**
     * Name of the Monitor Provider
     * @type {string}
     * @memberof EntryCacheMonitorProviderResponseAllOf
     */
    'id'?: string;
    /**
     * Indicates whether the Monitor Provider is enabled for use.
     * @type {boolean}
     * @memberof EntryCacheMonitorProviderResponseAllOf
     */
    'enabled'?: boolean;
}

