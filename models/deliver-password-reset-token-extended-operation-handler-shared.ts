/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumdeliverPasswordResetTokenExtendedOperationHandlerSchemaUrn } from './enumdeliver-password-reset-token-extended-operation-handler-schema-urn';

/**
 * 
 * @export
 * @interface DeliverPasswordResetTokenExtendedOperationHandlerShared
 */
export interface DeliverPasswordResetTokenExtendedOperationHandlerShared {
    /**
     * A description for this Extended Operation Handler
     * @type {string}
     * @memberof DeliverPasswordResetTokenExtendedOperationHandlerShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumdeliverPasswordResetTokenExtendedOperationHandlerSchemaUrn>}
     * @memberof DeliverPasswordResetTokenExtendedOperationHandlerShared
     */
    'schemas': Array<EnumdeliverPasswordResetTokenExtendedOperationHandlerSchemaUrn>;
    /**
     * The password generator that will be used to create the password reset token values to be delivered to the end user.
     * @type {string}
     * @memberof DeliverPasswordResetTokenExtendedOperationHandlerShared
     */
    'passwordGenerator': string;
    /**
     * The set of delivery mechanisms that may be used to deliver password reset tokens to users for requests that do not specify one or more preferred delivery mechanisms.
     * @type {Array<string>}
     * @memberof DeliverPasswordResetTokenExtendedOperationHandlerShared
     */
    'defaultTokenDeliveryMechanism': Array<string>;
    /**
     * The maximum length of time that a password reset token should be considered valid.
     * @type {string}
     * @memberof DeliverPasswordResetTokenExtendedOperationHandlerShared
     */
    'passwordResetTokenValidityDuration'?: string;
    /**
     * Indicates whether the Extended Operation Handler is enabled (that is, whether the types of extended operations are allowed in the server).
     * @type {boolean}
     * @memberof DeliverPasswordResetTokenExtendedOperationHandlerShared
     */
    'enabled': boolean;
}

