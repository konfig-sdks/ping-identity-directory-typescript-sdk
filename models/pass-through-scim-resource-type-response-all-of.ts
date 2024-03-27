/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumpassThroughScimResourceTypeSchemaUrn } from './enumpass-through-scim-resource-type-schema-urn';
import { EnumscimResourceTypeSchemaCheckingOptionProp } from './enumscim-resource-type-schema-checking-option-prop';

/**
 * 
 * @export
 * @interface PassThroughScimResourceTypeResponseAllOf
 */
export interface PassThroughScimResourceTypeResponseAllOf {
    /**
     * A description for this SCIM Resource Type
     * @type {string}
     * @memberof PassThroughScimResourceTypeResponseAllOf
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumpassThroughScimResourceTypeSchemaUrn>}
     * @memberof PassThroughScimResourceTypeResponseAllOf
     */
    'schemas'?: Array<EnumpassThroughScimResourceTypeSchemaUrn>;
    /**
     * Name of the SCIM Resource Type
     * @type {string}
     * @memberof PassThroughScimResourceTypeResponseAllOf
     */
    'id'?: string;
    /**
     * Indicates whether the SCIM Resource Type is enabled.
     * @type {boolean}
     * @memberof PassThroughScimResourceTypeResponseAllOf
     */
    'enabled'?: boolean;
    /**
     * The HTTP addressable endpoint of this SCIM Resource Type relative to the \'/scim/v2\' base URL. Do not include a leading \'/\'.
     * @type {string}
     * @memberof PassThroughScimResourceTypeResponseAllOf
     */
    'endpoint'?: string;
    /**
     * The maximum number of resources that the SCIM Resource Type should \"look through\" in the course of processing a search request.
     * @type {number}
     * @memberof PassThroughScimResourceTypeResponseAllOf
     */
    'lookthroughLimit'?: number;
    /**
     * 
     * @type {Array<EnumscimResourceTypeSchemaCheckingOptionProp>}
     * @memberof PassThroughScimResourceTypeResponseAllOf
     */
    'schemaCheckingOption'?: Array<EnumscimResourceTypeSchemaCheckingOptionProp>;
    /**
     * Specifies the LDAP structural object class that should be exposed by this SCIM Resource Type.
     * @type {string}
     * @memberof PassThroughScimResourceTypeResponseAllOf
     */
    'structuralLDAPObjectclass'?: string;
    /**
     * Specifies an auxiliary LDAP object class that should be exposed by this SCIM Resource Type.
     * @type {Array<string>}
     * @memberof PassThroughScimResourceTypeResponseAllOf
     */
    'auxiliaryLDAPObjectclass'?: Array<string>;
    /**
     * Specifies the base DN of the branch of the LDAP directory that can be accessed by this SCIM Resource Type.
     * @type {string}
     * @memberof PassThroughScimResourceTypeResponseAllOf
     */
    'includeBaseDN'?: string;
    /**
     * The set of LDAP filters that define the LDAP entries that should be included in this SCIM Resource Type.
     * @type {Array<string>}
     * @memberof PassThroughScimResourceTypeResponseAllOf
     */
    'includeFilter'?: Array<string>;
    /**
     * Specifies the set of operational LDAP attributes to be provided by this SCIM Resource Type.
     * @type {Array<string>}
     * @memberof PassThroughScimResourceTypeResponseAllOf
     */
    'includeOperationalAttribute'?: Array<string>;
    /**
     * Specifies the template to use for the DN when creating new entries.
     * @type {string}
     * @memberof PassThroughScimResourceTypeResponseAllOf
     */
    'createDNPattern'?: string;
}

