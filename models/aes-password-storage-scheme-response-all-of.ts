/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumaesPasswordStorageSchemeSchemaUrn } from './enumaes-password-storage-scheme-schema-urn';

/**
 * 
 * @export
 * @interface AesPasswordStorageSchemeResponseAllOf
 */
export interface AesPasswordStorageSchemeResponseAllOf {
    /**
     * A description for this Password Storage Scheme
     * @type {string}
     * @memberof AesPasswordStorageSchemeResponseAllOf
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumaesPasswordStorageSchemeSchemaUrn>}
     * @memberof AesPasswordStorageSchemeResponseAllOf
     */
    'schemas'?: Array<EnumaesPasswordStorageSchemeSchemaUrn>;
    /**
     * Name of the Password Storage Scheme
     * @type {string}
     * @memberof AesPasswordStorageSchemeResponseAllOf
     */
    'id'?: string;
    /**
     * Indicates whether the Password Storage Scheme is enabled for use.
     * @type {boolean}
     * @memberof AesPasswordStorageSchemeResponseAllOf
     */
    'enabled'?: boolean;
}

