/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumdefaultUncachedAttributeCriteriaSchemaUrn } from './enumdefault-uncached-attribute-criteria-schema-urn';

/**
 * 
 * @export
 * @interface DefaultUncachedAttributeCriteriaShared
 */
export interface DefaultUncachedAttributeCriteriaShared {
    /**
     * A description for this Uncached Attribute Criteria
     * @type {string}
     * @memberof DefaultUncachedAttributeCriteriaShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumdefaultUncachedAttributeCriteriaSchemaUrn>}
     * @memberof DefaultUncachedAttributeCriteriaShared
     */
    'schemas': Array<EnumdefaultUncachedAttributeCriteriaSchemaUrn>;
    /**
     * Indicates whether this Uncached Attribute Criteria is enabled for use in the server.
     * @type {boolean}
     * @memberof DefaultUncachedAttributeCriteriaShared
     */
    'enabled': boolean;
}

