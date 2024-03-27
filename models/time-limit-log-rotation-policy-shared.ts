/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumtimeLimitLogRotationPolicySchemaUrn } from './enumtime-limit-log-rotation-policy-schema-urn';

/**
 * 
 * @export
 * @interface TimeLimitLogRotationPolicyShared
 */
export interface TimeLimitLogRotationPolicyShared {
    /**
     * A description for this Log Rotation Policy
     * @type {string}
     * @memberof TimeLimitLogRotationPolicyShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumtimeLimitLogRotationPolicySchemaUrn>}
     * @memberof TimeLimitLogRotationPolicyShared
     */
    'schemas': Array<EnumtimeLimitLogRotationPolicySchemaUrn>;
    /**
     * Specifies the time interval between rotations.
     * @type {string}
     * @memberof TimeLimitLogRotationPolicyShared
     */
    'rotationInterval': string;
}

