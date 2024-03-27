/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumthirdPartyPasswordStorageSchemeSchemaUrn } from './enumthird-party-password-storage-scheme-schema-urn';

/**
 * 
 * @export
 * @interface ThirdPartyPasswordStorageSchemeShared
 */
export interface ThirdPartyPasswordStorageSchemeShared {
    /**
     * A description for this Password Storage Scheme
     * @type {string}
     * @memberof ThirdPartyPasswordStorageSchemeShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumthirdPartyPasswordStorageSchemeSchemaUrn>}
     * @memberof ThirdPartyPasswordStorageSchemeShared
     */
    'schemas': Array<EnumthirdPartyPasswordStorageSchemeSchemaUrn>;
    /**
     * The fully-qualified name of the Java class providing the logic for the Third Party Password Storage Scheme.
     * @type {string}
     * @memberof ThirdPartyPasswordStorageSchemeShared
     */
    'extensionClass': string;
    /**
     * The set of arguments used to customize the behavior for the Third Party Password Storage Scheme. Each configuration property should be given in the form \'name=value\'.
     * @type {Array<string>}
     * @memberof ThirdPartyPasswordStorageSchemeShared
     */
    'extensionArgument'?: Array<string>;
    /**
     * Indicates whether the Password Storage Scheme is enabled for use.
     * @type {boolean}
     * @memberof ThirdPartyPasswordStorageSchemeShared
     */
    'enabled': boolean;
}

