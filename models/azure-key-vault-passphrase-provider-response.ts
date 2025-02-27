/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { AzureKeyVaultPassphraseProviderShared } from './azure-key-vault-passphrase-provider-shared';
import { EnumazureKeyVaultPassphraseProviderSchemaUrn } from './enumazure-key-vault-passphrase-provider-schema-urn';
import { EnvironmentVariablePassphraseProviderResponseAllOf } from './environment-variable-passphrase-provider-response-all-of';
import { Meta } from './meta';
import { MetaMeta } from './meta-meta';
import { MetaUrnPingidentitySchemasConfigurationMessages20 } from './meta-urn-pingidentity-schemas-configuration-messages20';

/**
 * @type AzureKeyVaultPassphraseProviderResponse
 * @export
 */
export type AzureKeyVaultPassphraseProviderResponse = AzureKeyVaultPassphraseProviderShared & EnvironmentVariablePassphraseProviderResponseAllOf & Meta;


