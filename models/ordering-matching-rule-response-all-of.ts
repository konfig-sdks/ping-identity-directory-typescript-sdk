/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumorderingMatchingRuleSchemaUrn } from './enumordering-matching-rule-schema-urn';

/**
 * 
 * @export
 * @interface OrderingMatchingRuleResponseAllOf
 */
export interface OrderingMatchingRuleResponseAllOf {
    /**
     * 
     * @type {Array<EnumorderingMatchingRuleSchemaUrn>}
     * @memberof OrderingMatchingRuleResponseAllOf
     */
    'schemas'?: Array<EnumorderingMatchingRuleSchemaUrn>;
    /**
     * Name of the Matching Rule
     * @type {string}
     * @memberof OrderingMatchingRuleResponseAllOf
     */
    'id'?: string;
    /**
     * Indicates whether the Matching Rule is enabled for use.
     * @type {boolean}
     * @memberof OrderingMatchingRuleResponseAllOf
     */
    'enabled'?: boolean;
}

