/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumfileBasedCipherStreamProviderSchemaUrn } from './enumfile-based-cipher-stream-provider-schema-urn';

/**
 * 
 * @export
 * @interface FileBasedCipherStreamProviderShared
 */
export interface FileBasedCipherStreamProviderShared {
    /**
     * A description for this Cipher Stream Provider
     * @type {string}
     * @memberof FileBasedCipherStreamProviderShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumfileBasedCipherStreamProviderSchemaUrn>}
     * @memberof FileBasedCipherStreamProviderShared
     */
    'schemas': Array<EnumfileBasedCipherStreamProviderSchemaUrn>;
    /**
     * The path to the file containing the password to use when generating ciphers.
     * @type {string}
     * @memberof FileBasedCipherStreamProviderShared
     */
    'passwordFile': string;
    /**
     * Indicates whether the server should wait for the password file to become available if it does not exist.
     * @type {boolean}
     * @memberof FileBasedCipherStreamProviderShared
     */
    'waitForPasswordFile'?: boolean;
    /**
     * The path to a file that will hold metadata about the encryption performed by this File Based Cipher Stream Provider.
     * @type {string}
     * @memberof FileBasedCipherStreamProviderShared
     */
    'encryptionMetadataFile'?: string;
    /**
     * The PBKDF2 iteration count that will be used when deriving the encryption key used to protect the encryption settings database.
     * @type {number}
     * @memberof FileBasedCipherStreamProviderShared
     */
    'iterationCount'?: number;
    /**
     * Indicates whether this Cipher Stream Provider is enabled for use in the Directory Server.
     * @type {boolean}
     * @memberof FileBasedCipherStreamProviderShared
     */
    'enabled': boolean;
}

