/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumstringArrayTokenClaimValidationSchemaUrn } from './enumstring-array-token-claim-validation-schema-urn';

/**
 * 
 * @export
 * @interface StringArrayTokenClaimValidationShared
 */
export interface StringArrayTokenClaimValidationShared {
    /**
     * A description for this Token Claim Validation
     * @type {string}
     * @memberof StringArrayTokenClaimValidationShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumstringArrayTokenClaimValidationSchemaUrn>}
     * @memberof StringArrayTokenClaimValidationShared
     */
    'schemas': Array<EnumstringArrayTokenClaimValidationSchemaUrn>;
    /**
     * The set of all values that the claim must have to be considered valid.
     * @type {Array<string>}
     * @memberof StringArrayTokenClaimValidationShared
     */
    'allRequiredValue'?: Array<string>;
    /**
     * The set of values that the claim may have to be considered valid.
     * @type {Array<string>}
     * @memberof StringArrayTokenClaimValidationShared
     */
    'anyRequiredValue'?: Array<string>;
    /**
     * The name of the claim to be validated.
     * @type {string}
     * @memberof StringArrayTokenClaimValidationShared
     */
    'claimName': string;
}

