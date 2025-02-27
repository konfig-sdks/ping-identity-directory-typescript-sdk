/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { Enummd5PasswordStorageSchemeSchemaUrn } from './enummd5-password-storage-scheme-schema-urn';

/**
 * 
 * @export
 * @interface Md5PasswordStorageSchemeResponseAllOf
 */
export interface Md5PasswordStorageSchemeResponseAllOf {
    /**
     * A description for this Password Storage Scheme
     * @type {string}
     * @memberof Md5PasswordStorageSchemeResponseAllOf
     */
    'description'?: string;
    /**
     * 
     * @type {Array<Enummd5PasswordStorageSchemeSchemaUrn>}
     * @memberof Md5PasswordStorageSchemeResponseAllOf
     */
    'schemas'?: Array<Enummd5PasswordStorageSchemeSchemaUrn>;
    /**
     * Name of the Password Storage Scheme
     * @type {string}
     * @memberof Md5PasswordStorageSchemeResponseAllOf
     */
    'id'?: string;
    /**
     * Indicates whether the MD5 Password Storage Scheme is enabled for use.
     * @type {boolean}
     * @memberof Md5PasswordStorageSchemeResponseAllOf
     */
    'enabled'?: boolean;
}

