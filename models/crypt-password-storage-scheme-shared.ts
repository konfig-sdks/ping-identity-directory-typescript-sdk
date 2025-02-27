/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumcryptPasswordStorageSchemeSchemaUrn } from './enumcrypt-password-storage-scheme-schema-urn';
import { EnumpasswordStorageSchemePasswordEncodingMechanismProp } from './enumpassword-storage-scheme-password-encoding-mechanism-prop';

/**
 * 
 * @export
 * @interface CryptPasswordStorageSchemeShared
 */
export interface CryptPasswordStorageSchemeShared {
    /**
     * A description for this Password Storage Scheme
     * @type {string}
     * @memberof CryptPasswordStorageSchemeShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumcryptPasswordStorageSchemeSchemaUrn>}
     * @memberof CryptPasswordStorageSchemeShared
     */
    'schemas': Array<EnumcryptPasswordStorageSchemeSchemaUrn>;
    /**
     * Specifies the mechanism that should be used to encode clear-text passwords for use with this scheme.
     * @type {EnumpasswordStorageSchemePasswordEncodingMechanismProp}
     * @memberof CryptPasswordStorageSchemeShared
     */
    'passwordEncodingMechanism'?: EnumpasswordStorageSchemePasswordEncodingMechanismProp;
    /**
     * Specifies the number of digest rounds to use for the SHA-2 encodings. This will not be used for the legacy or MD5-based encodings.
     * @type {number}
     * @memberof CryptPasswordStorageSchemeShared
     */
    'numDigestRounds'?: number;
    /**
     * Specifies the maximum allowed length, in bytes, for passwords encoded with this scheme, which can help mitigate denial of service attacks from clients that attempt to bind with very long passwords.
     * @type {number}
     * @memberof CryptPasswordStorageSchemeShared
     */
    'maxPasswordLength'?: number;
    /**
     * Indicates whether the Password Storage Scheme is enabled for use.
     * @type {boolean}
     * @memberof CryptPasswordStorageSchemeShared
     */
    'enabled': boolean;
}

