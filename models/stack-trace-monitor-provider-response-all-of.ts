/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumstackTraceMonitorProviderSchemaUrn } from './enumstack-trace-monitor-provider-schema-urn';

/**
 * 
 * @export
 * @interface StackTraceMonitorProviderResponseAllOf
 */
export interface StackTraceMonitorProviderResponseAllOf {
    /**
     * A description for this Monitor Provider
     * @type {string}
     * @memberof StackTraceMonitorProviderResponseAllOf
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumstackTraceMonitorProviderSchemaUrn>}
     * @memberof StackTraceMonitorProviderResponseAllOf
     */
    'schemas'?: Array<EnumstackTraceMonitorProviderSchemaUrn>;
    /**
     * Name of the Monitor Provider
     * @type {string}
     * @memberof StackTraceMonitorProviderResponseAllOf
     */
    'id'?: string;
    /**
     * Indicates whether the Monitor Provider is enabled for use.
     * @type {boolean}
     * @memberof StackTraceMonitorProviderResponseAllOf
     */
    'enabled'?: boolean;
}

