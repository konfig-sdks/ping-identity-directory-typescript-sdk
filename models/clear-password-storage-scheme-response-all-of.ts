/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumclearPasswordStorageSchemeSchemaUrn } from './enumclear-password-storage-scheme-schema-urn';

/**
 * 
 * @export
 * @interface ClearPasswordStorageSchemeResponseAllOf
 */
export interface ClearPasswordStorageSchemeResponseAllOf {
    /**
     * A description for this Password Storage Scheme
     * @type {string}
     * @memberof ClearPasswordStorageSchemeResponseAllOf
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumclearPasswordStorageSchemeSchemaUrn>}
     * @memberof ClearPasswordStorageSchemeResponseAllOf
     */
    'schemas'?: Array<EnumclearPasswordStorageSchemeSchemaUrn>;
    /**
     * Name of the Password Storage Scheme
     * @type {string}
     * @memberof ClearPasswordStorageSchemeResponseAllOf
     */
    'id'?: string;
    /**
     * Indicates whether the Clear Password Storage Scheme is enabled for use.
     * @type {boolean}
     * @memberof ClearPasswordStorageSchemeResponseAllOf
     */
    'enabled'?: boolean;
}

