/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { Argon2dPasswordStorageSchemeResponseAllOf } from './argon2d-password-storage-scheme-response-all-of';
import { CryptPasswordStorageSchemeShared } from './crypt-password-storage-scheme-shared';
import { EnumcryptPasswordStorageSchemeSchemaUrn } from './enumcrypt-password-storage-scheme-schema-urn';
import { EnumpasswordStorageSchemePasswordEncodingMechanismProp } from './enumpassword-storage-scheme-password-encoding-mechanism-prop';
import { Meta } from './meta';
import { MetaMeta } from './meta-meta';
import { MetaUrnPingidentitySchemasConfigurationMessages20 } from './meta-urn-pingidentity-schemas-configuration-messages20';

/**
 * @type CryptPasswordStorageSchemeResponse
 * @export
 */
export type CryptPasswordStorageSchemeResponse = Argon2dPasswordStorageSchemeResponseAllOf & CryptPasswordStorageSchemeShared & Meta;


