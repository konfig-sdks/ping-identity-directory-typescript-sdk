/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumgroovyScriptedPasswordValidatorSchemaUrn } from './enumgroovy-scripted-password-validator-schema-urn';

/**
 * 
 * @export
 * @interface GroovyScriptedPasswordValidatorShared
 */
export interface GroovyScriptedPasswordValidatorShared {
    /**
     * A description for this Password Validator
     * @type {string}
     * @memberof GroovyScriptedPasswordValidatorShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumgroovyScriptedPasswordValidatorSchemaUrn>}
     * @memberof GroovyScriptedPasswordValidatorShared
     */
    'schemas': Array<EnumgroovyScriptedPasswordValidatorSchemaUrn>;
    /**
     * The fully-qualified name of the Groovy class providing the logic for the Groovy Scripted Password Validator.
     * @type {string}
     * @memberof GroovyScriptedPasswordValidatorShared
     */
    'scriptClass': string;
    /**
     * The set of arguments used to customize the behavior for the Scripted Password Validator. Each configuration property should be given in the form \'name=value\'.
     * @type {Array<string>}
     * @memberof GroovyScriptedPasswordValidatorShared
     */
    'scriptArgument'?: Array<string>;
    /**
     * Indicates whether the password validator is enabled for use.
     * @type {boolean}
     * @memberof GroovyScriptedPasswordValidatorShared
     */
    'enabled': boolean;
    /**
     * Specifies a message that can be used to describe the requirements imposed by this password validator to end users. If a value is provided for this property, then it will override any description that may have otherwise been generated by the validator.
     * @type {string}
     * @memberof GroovyScriptedPasswordValidatorShared
     */
    'validatorRequirementDescription'?: string;
    /**
     * Specifies a message that may be provided to the end user in the event that a proposed password is rejected by this validator. If a value is provided for this property, then it will override any failure message that may have otherwise been generated by the validator.
     * @type {string}
     * @memberof GroovyScriptedPasswordValidatorShared
     */
    'validatorFailureMessage'?: string;
}

