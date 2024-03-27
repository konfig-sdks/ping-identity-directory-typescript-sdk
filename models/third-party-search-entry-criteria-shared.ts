/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumthirdPartySearchEntryCriteriaSchemaUrn } from './enumthird-party-search-entry-criteria-schema-urn';

/**
 * 
 * @export
 * @interface ThirdPartySearchEntryCriteriaShared
 */
export interface ThirdPartySearchEntryCriteriaShared {
    /**
     * A description for this Search Entry Criteria
     * @type {string}
     * @memberof ThirdPartySearchEntryCriteriaShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumthirdPartySearchEntryCriteriaSchemaUrn>}
     * @memberof ThirdPartySearchEntryCriteriaShared
     */
    'schemas': Array<EnumthirdPartySearchEntryCriteriaSchemaUrn>;
    /**
     * The fully-qualified name of the Java class providing the logic for the Third Party Search Entry Criteria.
     * @type {string}
     * @memberof ThirdPartySearchEntryCriteriaShared
     */
    'extensionClass': string;
    /**
     * The set of arguments used to customize the behavior for the Third Party Search Entry Criteria. Each configuration property should be given in the form \'name=value\'.
     * @type {Array<string>}
     * @memberof ThirdPartySearchEntryCriteriaShared
     */
    'extensionArgument'?: Array<string>;
}

