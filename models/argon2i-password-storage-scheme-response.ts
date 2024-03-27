/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { Argon2dPasswordStorageSchemeResponseAllOf } from './argon2d-password-storage-scheme-response-all-of';
import { Argon2iPasswordStorageSchemeShared } from './argon2i-password-storage-scheme-shared';
import { Enumargon2iPasswordStorageSchemeSchemaUrn } from './enumargon2i-password-storage-scheme-schema-urn';
import { Meta } from './meta';
import { MetaMeta } from './meta-meta';
import { MetaUrnPingidentitySchemasConfigurationMessages20 } from './meta-urn-pingidentity-schemas-configuration-messages20';

/**
 * @type Argon2iPasswordStorageSchemeResponse
 * @export
 */
export type Argon2iPasswordStorageSchemeResponse = Argon2dPasswordStorageSchemeResponseAllOf & Argon2iPasswordStorageSchemeShared & Meta;


