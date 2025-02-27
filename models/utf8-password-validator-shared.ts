/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumpasswordValidatorAllowedCharacterTypeProp } from './enumpassword-validator-allowed-character-type-prop';
import { Enumutf8PasswordValidatorSchemaUrn } from './enumutf8-password-validator-schema-urn';

/**
 * 
 * @export
 * @interface Utf8PasswordValidatorShared
 */
export interface Utf8PasswordValidatorShared {
    /**
     * A description for this Password Validator
     * @type {string}
     * @memberof Utf8PasswordValidatorShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<Enumutf8PasswordValidatorSchemaUrn>}
     * @memberof Utf8PasswordValidatorShared
     */
    'schemas': Array<Enumutf8PasswordValidatorSchemaUrn>;
    /**
     * Indicates whether passwords will be allowed to include characters from outside the ASCII character set.
     * @type {boolean}
     * @memberof Utf8PasswordValidatorShared
     */
    'allowNonAsciiCharacters'?: boolean;
    /**
     * Indicates whether passwords will be allowed to include characters that are not recognized by the JVM\'s Unicode support.
     * @type {boolean}
     * @memberof Utf8PasswordValidatorShared
     */
    'allowUnknownCharacters'?: boolean;
    /**
     * 
     * @type {Array<EnumpasswordValidatorAllowedCharacterTypeProp>}
     * @memberof Utf8PasswordValidatorShared
     */
    'allowedCharacterType'?: Array<EnumpasswordValidatorAllowedCharacterTypeProp>;
    /**
     * Indicates whether the password validator is enabled for use.
     * @type {boolean}
     * @memberof Utf8PasswordValidatorShared
     */
    'enabled': boolean;
    /**
     * Specifies a message that can be used to describe the requirements imposed by this password validator to end users. If a value is provided for this property, then it will override any description that may have otherwise been generated by the validator.
     * @type {string}
     * @memberof Utf8PasswordValidatorShared
     */
    'validatorRequirementDescription'?: string;
    /**
     * Specifies a message that may be provided to the end user in the event that a proposed password is rejected by this validator. If a value is provided for this property, then it will override any failure message that may have otherwise been generated by the validator.
     * @type {string}
     * @memberof Utf8PasswordValidatorShared
     */
    'validatorFailureMessage'?: string;
}

