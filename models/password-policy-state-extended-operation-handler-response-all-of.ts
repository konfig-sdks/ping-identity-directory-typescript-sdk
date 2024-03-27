/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumpasswordPolicyStateExtendedOperationHandlerSchemaUrn } from './enumpassword-policy-state-extended-operation-handler-schema-urn';

/**
 * 
 * @export
 * @interface PasswordPolicyStateExtendedOperationHandlerResponseAllOf
 */
export interface PasswordPolicyStateExtendedOperationHandlerResponseAllOf {
    /**
     * A description for this Extended Operation Handler
     * @type {string}
     * @memberof PasswordPolicyStateExtendedOperationHandlerResponseAllOf
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumpasswordPolicyStateExtendedOperationHandlerSchemaUrn>}
     * @memberof PasswordPolicyStateExtendedOperationHandlerResponseAllOf
     */
    'schemas'?: Array<EnumpasswordPolicyStateExtendedOperationHandlerSchemaUrn>;
    /**
     * Name of the Extended Operation Handler
     * @type {string}
     * @memberof PasswordPolicyStateExtendedOperationHandlerResponseAllOf
     */
    'id'?: string;
    /**
     * Indicates whether the Extended Operation Handler is enabled (that is, whether the types of extended operations are allowed in the server).
     * @type {boolean}
     * @memberof PasswordPolicyStateExtendedOperationHandlerResponseAllOf
     */
    'enabled'?: boolean;
}

