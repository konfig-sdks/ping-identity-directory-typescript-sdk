/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumsingleUseTokensExtendedOperationHandlerSchemaUrn } from './enumsingle-use-tokens-extended-operation-handler-schema-urn';

/**
 * 
 * @export
 * @interface SingleUseTokensExtendedOperationHandlerShared
 */
export interface SingleUseTokensExtendedOperationHandlerShared {
    /**
     * A description for this Extended Operation Handler
     * @type {string}
     * @memberof SingleUseTokensExtendedOperationHandlerShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumsingleUseTokensExtendedOperationHandlerSchemaUrn>}
     * @memberof SingleUseTokensExtendedOperationHandlerShared
     */
    'schemas': Array<EnumsingleUseTokensExtendedOperationHandlerSchemaUrn>;
    /**
     * The password generator that will be used to create the single-use token values to be delivered to the end user.
     * @type {string}
     * @memberof SingleUseTokensExtendedOperationHandlerShared
     */
    'passwordGenerator': string;
    /**
     * The set of delivery mechanisms that may be used to deliver single-use tokens to users in requests that do not specify one or more preferred delivery mechanisms.
     * @type {Array<string>}
     * @memberof SingleUseTokensExtendedOperationHandlerShared
     */
    'defaultOTPDeliveryMechanism': Array<string>;
    /**
     * The default length of time that a single-use token will be considered valid by the server if the client doesn\'t specify a duration in the deliver single-use token request.
     * @type {string}
     * @memberof SingleUseTokensExtendedOperationHandlerShared
     */
    'defaultSingleUseTokenValidityDuration'?: string;
    /**
     * Indicates whether the Extended Operation Handler is enabled (that is, whether the types of extended operations are allowed in the server).
     * @type {boolean}
     * @memberof SingleUseTokensExtendedOperationHandlerShared
     */
    'enabled': boolean;
}

