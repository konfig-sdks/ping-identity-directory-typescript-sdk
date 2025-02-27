/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumldapUrlAttributeSyntaxSchemaUrn } from './enumldap-url-attribute-syntax-schema-urn';

/**
 * 
 * @export
 * @interface LdapUrlAttributeSyntaxResponseAllOf
 */
export interface LdapUrlAttributeSyntaxResponseAllOf {
    /**
     * 
     * @type {Array<EnumldapUrlAttributeSyntaxSchemaUrn>}
     * @memberof LdapUrlAttributeSyntaxResponseAllOf
     */
    'schemas'?: Array<EnumldapUrlAttributeSyntaxSchemaUrn>;
    /**
     * Name of the Attribute Syntax
     * @type {string}
     * @memberof LdapUrlAttributeSyntaxResponseAllOf
     */
    'id'?: string;
    /**
     * Indicates whether values for attributes with this syntax will be required to be in the valid LDAP URL format. If this is set to false, then arbitrary strings will be allowed.
     * @type {boolean}
     * @memberof LdapUrlAttributeSyntaxResponseAllOf
     */
    'strictFormat'?: boolean;
    /**
     * Indicates whether the Attribute Syntax is enabled.
     * @type {boolean}
     * @memberof LdapUrlAttributeSyntaxResponseAllOf
     */
    'enabled'?: boolean;
    /**
     * Indicates whether values of this attribute are required to have a \"binary\" transfer option as described in RFC 4522. Attributes with this syntax will generally be referenced with names including \";binary\" (e.g., \"userCertificate;binary\").
     * @type {boolean}
     * @memberof LdapUrlAttributeSyntaxResponseAllOf
     */
    'requireBinaryTransfer'?: boolean;
}

