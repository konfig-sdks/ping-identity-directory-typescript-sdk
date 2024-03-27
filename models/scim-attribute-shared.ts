/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumscimAttributeMutabilityProp } from './enumscim-attribute-mutability-prop';
import { EnumscimAttributeReturnedProp } from './enumscim-attribute-returned-prop';
import { EnumscimAttributeSchemaUrn } from './enumscim-attribute-schema-urn';
import { EnumscimAttributeTypeProp } from './enumscim-attribute-type-prop';

/**
 * 
 * @export
 * @interface ScimAttributeShared
 */
export interface ScimAttributeShared {
    /**
     * A description for this SCIM Attribute
     * @type {string}
     * @memberof ScimAttributeShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumscimAttributeSchemaUrn>}
     * @memberof ScimAttributeShared
     */
    'schemas'?: Array<EnumscimAttributeSchemaUrn>;
    /**
     * The name of the attribute.
     * @type {string}
     * @memberof ScimAttributeShared
     */
    'name': string;
    /**
     * Specifies the data type for this attribute.
     * @type {EnumscimAttributeTypeProp}
     * @memberof ScimAttributeShared
     */
    'type'?: EnumscimAttributeTypeProp;
    /**
     * Specifies whether this attribute is required.
     * @type {boolean}
     * @memberof ScimAttributeShared
     */
    'required'?: boolean;
    /**
     * Specifies whether the attribute values are case sensitive.
     * @type {boolean}
     * @memberof ScimAttributeShared
     */
    'caseExact'?: boolean;
    /**
     * Specifies whether this attribute may have multiple values.
     * @type {boolean}
     * @memberof ScimAttributeShared
     */
    'multiValued'?: boolean;
    /**
     * Specifies the suggested canonical type values for the attribute.
     * @type {Array<string>}
     * @memberof ScimAttributeShared
     */
    'canonicalValue'?: Array<string>;
    /**
     * Specifies the circumstances under which the values of the attribute can be written.
     * @type {EnumscimAttributeMutabilityProp}
     * @memberof ScimAttributeShared
     */
    'mutability'?: EnumscimAttributeMutabilityProp;
    /**
     * Specifies the circumstances under which the values of the attribute are returned in response to a request.
     * @type {EnumscimAttributeReturnedProp}
     * @memberof ScimAttributeShared
     */
    'returned'?: EnumscimAttributeReturnedProp;
    /**
     * Specifies the SCIM resource types that may be referenced. This property is only applicable for attributes that are of type \'reference\'. Valid values are: A SCIM resource type (e.g., \'User\' or \'Group\'), \'external\' - indicating the resource is an external resource (e.g., such as a photo), or \'uri\' - indicating that the reference is to a service endpoint or an identifier (such as a schema urn).
     * @type {Array<string>}
     * @memberof ScimAttributeShared
     */
    'referenceType'?: Array<string>;
}

