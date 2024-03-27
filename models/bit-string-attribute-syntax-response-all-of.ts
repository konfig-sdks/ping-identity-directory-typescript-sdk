/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumbitStringAttributeSyntaxSchemaUrn } from './enumbit-string-attribute-syntax-schema-urn';

/**
 * 
 * @export
 * @interface BitStringAttributeSyntaxResponseAllOf
 */
export interface BitStringAttributeSyntaxResponseAllOf {
    /**
     * 
     * @type {Array<EnumbitStringAttributeSyntaxSchemaUrn>}
     * @memberof BitStringAttributeSyntaxResponseAllOf
     */
    'schemas'?: Array<EnumbitStringAttributeSyntaxSchemaUrn>;
    /**
     * Name of the Attribute Syntax
     * @type {string}
     * @memberof BitStringAttributeSyntaxResponseAllOf
     */
    'id'?: string;
    /**
     * Indicates whether values of attributes with this syntax should be compacted when stored in a local DB database.
     * @type {boolean}
     * @memberof BitStringAttributeSyntaxResponseAllOf
     */
    'enableCompaction'?: boolean;
    /**
     * Specifies the specific attributes (which should be associated with this syntax) whose values should be compacted. If one or more include attributes are specified, then only those attributes will have their values compacted. If not set then all attributes will have their values compacted. The exclude-attribute-from-compaction property takes precedence over this property.
     * @type {Array<string>}
     * @memberof BitStringAttributeSyntaxResponseAllOf
     */
    'includeAttributeInCompaction'?: Array<string>;
    /**
     * Specifies the specific attributes (which should be associated with this syntax) whose values should not be compacted. If one or more exclude attributes are specified, then values of those attributes will not have their values compacted. This property takes precedence over the include-attribute-in-compaction property.
     * @type {Array<string>}
     * @memberof BitStringAttributeSyntaxResponseAllOf
     */
    'excludeAttributeFromCompaction'?: Array<string>;
    /**
     * Indicates whether the Attribute Syntax is enabled.
     * @type {boolean}
     * @memberof BitStringAttributeSyntaxResponseAllOf
     */
    'enabled'?: boolean;
    /**
     * Indicates whether values of this attribute are required to have a \"binary\" transfer option as described in RFC 4522. Attributes with this syntax will generally be referenced with names including \";binary\" (e.g., \"userCertificate;binary\").
     * @type {boolean}
     * @memberof BitStringAttributeSyntaxResponseAllOf
     */
    'requireBinaryTransfer'?: boolean;
}

