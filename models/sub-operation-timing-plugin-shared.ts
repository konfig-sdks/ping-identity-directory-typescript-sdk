/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumpluginPluginTypeProp } from './enumplugin-plugin-type-prop';
import { EnumsubOperationTimingPluginSchemaUrn } from './enumsub-operation-timing-plugin-schema-urn';

/**
 * 
 * @export
 * @interface SubOperationTimingPluginShared
 */
export interface SubOperationTimingPluginShared {
    /**
     * A description for this Plugin
     * @type {string}
     * @memberof SubOperationTimingPluginShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumsubOperationTimingPluginSchemaUrn>}
     * @memberof SubOperationTimingPluginShared
     */
    'schemas': Array<EnumsubOperationTimingPluginSchemaUrn>;
    /**
     * 
     * @type {Array<EnumpluginPluginTypeProp>}
     * @memberof SubOperationTimingPluginShared
     */
    'pluginType'?: Array<EnumpluginPluginTypeProp>;
    /**
     * Specifies a set of request criteria used to indicate that only operations for requests matching this criteria should be counted when aggregating timing data.
     * @type {string}
     * @memberof SubOperationTimingPluginShared
     */
    'requestCriteria'?: string;
    /**
     * This controls how many of the most expensive phases are included per operation type in the monitor entry.
     * @type {number}
     * @memberof SubOperationTimingPluginShared
     */
    'numMostExpensivePhasesShown'?: number;
    /**
     * Indicates whether the plug-in should be invoked for internal operations.
     * @type {boolean}
     * @memberof SubOperationTimingPluginShared
     */
    'invokeForInternalOperations'?: boolean;
    /**
     * Indicates whether the plug-in is enabled for use.
     * @type {boolean}
     * @memberof SubOperationTimingPluginShared
     */
    'enabled': boolean;
}

