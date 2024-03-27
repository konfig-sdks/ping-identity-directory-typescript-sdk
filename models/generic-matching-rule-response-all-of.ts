/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumgenericMatchingRuleSchemaUrn } from './enumgeneric-matching-rule-schema-urn';

/**
 * 
 * @export
 * @interface GenericMatchingRuleResponseAllOf
 */
export interface GenericMatchingRuleResponseAllOf {
    /**
     * 
     * @type {Array<EnumgenericMatchingRuleSchemaUrn>}
     * @memberof GenericMatchingRuleResponseAllOf
     */
    'schemas'?: Array<EnumgenericMatchingRuleSchemaUrn>;
    /**
     * Name of the Matching Rule
     * @type {string}
     * @memberof GenericMatchingRuleResponseAllOf
     */
    'id'?: string;
    /**
     * Indicates whether the Matching Rule is enabled for use.
     * @type {boolean}
     * @memberof GenericMatchingRuleResponseAllOf
     */
    'enabled'?: boolean;
}

