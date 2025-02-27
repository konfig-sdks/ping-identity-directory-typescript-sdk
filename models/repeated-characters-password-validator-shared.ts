/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumrepeatedCharactersPasswordValidatorSchemaUrn } from './enumrepeated-characters-password-validator-schema-urn';

/**
 * 
 * @export
 * @interface RepeatedCharactersPasswordValidatorShared
 */
export interface RepeatedCharactersPasswordValidatorShared {
    /**
     * A description for this Password Validator
     * @type {string}
     * @memberof RepeatedCharactersPasswordValidatorShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumrepeatedCharactersPasswordValidatorSchemaUrn>}
     * @memberof RepeatedCharactersPasswordValidatorShared
     */
    'schemas': Array<EnumrepeatedCharactersPasswordValidatorSchemaUrn>;
    /**
     * Specifies the maximum number of times that any character can appear consecutively in a password value.
     * @type {number}
     * @memberof RepeatedCharactersPasswordValidatorShared
     */
    'maxConsecutiveLength': number;
    /**
     * Indicates whether this password validator should treat password characters in a case-sensitive manner.
     * @type {boolean}
     * @memberof RepeatedCharactersPasswordValidatorShared
     */
    'caseSensitiveValidation': boolean;
    /**
     * Specifies a set of characters that should be considered equivalent for the purpose of this password validator. This can be used, for example, to ensure that passwords contain no more than three consecutive digits.
     * @type {Array<string>}
     * @memberof RepeatedCharactersPasswordValidatorShared
     */
    'characterSet'?: Array<string>;
    /**
     * Indicates whether the password validator is enabled for use.
     * @type {boolean}
     * @memberof RepeatedCharactersPasswordValidatorShared
     */
    'enabled': boolean;
    /**
     * Specifies a message that can be used to describe the requirements imposed by this password validator to end users. If a value is provided for this property, then it will override any description that may have otherwise been generated by the validator.
     * @type {string}
     * @memberof RepeatedCharactersPasswordValidatorShared
     */
    'validatorRequirementDescription'?: string;
    /**
     * Specifies a message that may be provided to the end user in the event that a proposed password is rejected by this validator. If a value is provided for this property, then it will override any failure message that may have otherwise been generated by the validator.
     * @type {string}
     * @memberof RepeatedCharactersPasswordValidatorShared
     */
    'validatorFailureMessage'?: string;
}

