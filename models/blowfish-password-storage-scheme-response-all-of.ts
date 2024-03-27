/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumblowfishPasswordStorageSchemeSchemaUrn } from './enumblowfish-password-storage-scheme-schema-urn';

/**
 * 
 * @export
 * @interface BlowfishPasswordStorageSchemeResponseAllOf
 */
export interface BlowfishPasswordStorageSchemeResponseAllOf {
    /**
     * A description for this Password Storage Scheme
     * @type {string}
     * @memberof BlowfishPasswordStorageSchemeResponseAllOf
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumblowfishPasswordStorageSchemeSchemaUrn>}
     * @memberof BlowfishPasswordStorageSchemeResponseAllOf
     */
    'schemas'?: Array<EnumblowfishPasswordStorageSchemeSchemaUrn>;
    /**
     * Name of the Password Storage Scheme
     * @type {string}
     * @memberof BlowfishPasswordStorageSchemeResponseAllOf
     */
    'id'?: string;
    /**
     * Indicates whether the Password Storage Scheme is enabled for use.
     * @type {boolean}
     * @memberof BlowfishPasswordStorageSchemeResponseAllOf
     */
    'enabled'?: boolean;
}

