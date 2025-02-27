/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumscryptPasswordStorageSchemeSchemaUrn } from './enumscrypt-password-storage-scheme-schema-urn';

/**
 * 
 * @export
 * @interface ScryptPasswordStorageSchemeShared
 */
export interface ScryptPasswordStorageSchemeShared {
    /**
     * A description for this Password Storage Scheme
     * @type {string}
     * @memberof ScryptPasswordStorageSchemeShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumscryptPasswordStorageSchemeSchemaUrn>}
     * @memberof ScryptPasswordStorageSchemeShared
     */
    'schemas': Array<EnumscryptPasswordStorageSchemeSchemaUrn>;
    /**
     * Specifies the exponent that should be used for the CPU/memory cost factor. The cost factor must be a power of two, so the value of this property represents the power to which two is raised. The CPU/memory cost factor specifies the number of iterations required for encoding the password, and also affects the amount of memory required during processing. A higher cost factor requires more processing and more memory to generate a password, which makes attacks against the password more expensive.
     * @type {number}
     * @memberof ScryptPasswordStorageSchemeShared
     */
    'scryptCpuMemoryCostFactorExponent'?: number;
    /**
     * Specifies the block size for the digest that will be used in the course of encoding passwords. Increasing the block size while keeping the CPU/memory cost factor constant will increase the amount of memory required to encode a password, but it also increases the ratio of sequential memory access to random memory access (and sequential memory access is generally faster than random memory access).
     * @type {number}
     * @memberof ScryptPasswordStorageSchemeShared
     */
    'scryptBlockSize'?: number;
    /**
     * Specifies the number of times that scrypt has to perform the entire encoding process to produce the final result.
     * @type {number}
     * @memberof ScryptPasswordStorageSchemeShared
     */
    'scryptParallelizationParameter'?: number;
    /**
     * Specifies the maximum allowed length, in bytes, for passwords encoded with this scheme, which can help mitigate denial of service attacks from clients that attempt to bind with very long passwords.
     * @type {number}
     * @memberof ScryptPasswordStorageSchemeShared
     */
    'maxPasswordLength'?: number;
    /**
     * Indicates whether the Password Storage Scheme is enabled for use.
     * @type {boolean}
     * @memberof ScryptPasswordStorageSchemeShared
     */
    'enabled': boolean;
}

