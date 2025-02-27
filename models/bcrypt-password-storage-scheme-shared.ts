/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumbcryptPasswordStorageSchemeSchemaUrn } from './enumbcrypt-password-storage-scheme-schema-urn';

/**
 * 
 * @export
 * @interface BcryptPasswordStorageSchemeShared
 */
export interface BcryptPasswordStorageSchemeShared {
    /**
     * A description for this Password Storage Scheme
     * @type {string}
     * @memberof BcryptPasswordStorageSchemeShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumbcryptPasswordStorageSchemeSchemaUrn>}
     * @memberof BcryptPasswordStorageSchemeShared
     */
    'schemas': Array<EnumbcryptPasswordStorageSchemeSchemaUrn>;
    /**
     * Specifies the cost factor to use when encoding passwords with Bcrypt. A higher cost factor requires more processing to generate a password, which makes attacks against the password more expensive.
     * @type {number}
     * @memberof BcryptPasswordStorageSchemeShared
     */
    'bcryptCostFactor'?: number;
    /**
     * Indicates whether the Password Storage Scheme is enabled for use.
     * @type {boolean}
     * @memberof BcryptPasswordStorageSchemeShared
     */
    'enabled': boolean;
}

