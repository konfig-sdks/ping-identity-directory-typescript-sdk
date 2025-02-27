/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumtelephoneNumberAttributeSyntaxSchemaUrn } from './enumtelephone-number-attribute-syntax-schema-urn';

/**
 * 
 * @export
 * @interface TelephoneNumberAttributeSyntaxResponseAllOf
 */
export interface TelephoneNumberAttributeSyntaxResponseAllOf {
    /**
     * 
     * @type {Array<EnumtelephoneNumberAttributeSyntaxSchemaUrn>}
     * @memberof TelephoneNumberAttributeSyntaxResponseAllOf
     */
    'schemas'?: Array<EnumtelephoneNumberAttributeSyntaxSchemaUrn>;
    /**
     * Name of the Attribute Syntax
     * @type {string}
     * @memberof TelephoneNumberAttributeSyntaxResponseAllOf
     */
    'id'?: string;
    /**
     * Indicates whether to require telephone number values to strictly comply with the standard definition for this syntax.
     * @type {boolean}
     * @memberof TelephoneNumberAttributeSyntaxResponseAllOf
     */
    'strictFormat'?: boolean;
    /**
     * Indicates whether the Attribute Syntax is enabled.
     * @type {boolean}
     * @memberof TelephoneNumberAttributeSyntaxResponseAllOf
     */
    'enabled'?: boolean;
    /**
     * Indicates whether values of this attribute are required to have a \"binary\" transfer option as described in RFC 4522. Attributes with this syntax will generally be referenced with names including \";binary\" (e.g., \"userCertificate;binary\").
     * @type {boolean}
     * @memberof TelephoneNumberAttributeSyntaxResponseAllOf
     */
    'requireBinaryTransfer'?: boolean;
}

