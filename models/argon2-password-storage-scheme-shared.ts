/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { Enumargon2PasswordStorageSchemeSchemaUrn } from './enumargon2-password-storage-scheme-schema-urn';

/**
 * 
 * @export
 * @interface Argon2PasswordStorageSchemeShared
 */
export interface Argon2PasswordStorageSchemeShared {
    /**
     * A description for this Password Storage Scheme
     * @type {string}
     * @memberof Argon2PasswordStorageSchemeShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<Enumargon2PasswordStorageSchemeSchemaUrn>}
     * @memberof Argon2PasswordStorageSchemeShared
     */
    'schemas': Array<Enumargon2PasswordStorageSchemeSchemaUrn>;
    /**
     * The number of rounds of cryptographic processing required in the course of encoding each password.
     * @type {number}
     * @memberof Argon2PasswordStorageSchemeShared
     */
    'iterationCount': number;
    /**
     * The number of concurrent threads that will be used in the course of encoding each password.
     * @type {number}
     * @memberof Argon2PasswordStorageSchemeShared
     */
    'parallelismFactor': number;
    /**
     * The number of kilobytes of memory that must be used in the course of encoding each password.
     * @type {number}
     * @memberof Argon2PasswordStorageSchemeShared
     */
    'memoryUsageKb': number;
    /**
     * The number of bytes to use for the generated salt.
     * @type {number}
     * @memberof Argon2PasswordStorageSchemeShared
     */
    'saltLengthBytes': number;
    /**
     * The number of bytes to use for the derived key. The value must be greater than or equal to 8 and less than or equal to 512.
     * @type {number}
     * @memberof Argon2PasswordStorageSchemeShared
     */
    'derivedKeyLengthBytes': number;
    /**
     * Indicates whether the Password Storage Scheme is enabled for use.
     * @type {boolean}
     * @memberof Argon2PasswordStorageSchemeShared
     */
    'enabled': boolean;
}

