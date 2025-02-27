/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { AmazonKeyManagementServiceCipherStreamProviderResponse } from './amazon-key-management-service-cipher-stream-provider-response';
import { AmazonSecretsManagerCipherStreamProviderResponse } from './amazon-secrets-manager-cipher-stream-provider-response';
import { AzureKeyVaultCipherStreamProviderResponse } from './azure-key-vault-cipher-stream-provider-response';
import { ConjurCipherStreamProviderResponse } from './conjur-cipher-stream-provider-response';
import { DefaultCipherStreamProviderResponse } from './default-cipher-stream-provider-response';
import { EnumthirdPartyCipherStreamProviderSchemaUrn } from './enumthird-party-cipher-stream-provider-schema-urn';
import { FileBasedCipherStreamProviderResponse } from './file-based-cipher-stream-provider-response';
import { MetaMeta } from './meta-meta';
import { MetaUrnPingidentitySchemasConfigurationMessages20 } from './meta-urn-pingidentity-schemas-configuration-messages20';
import { Pkcs11CipherStreamProviderResponse } from './pkcs11-cipher-stream-provider-response';
import { ThirdPartyCipherStreamProviderResponse } from './third-party-cipher-stream-provider-response';
import { VaultCipherStreamProviderResponse } from './vault-cipher-stream-provider-response';
import { WaitForPassphraseCipherStreamProviderResponse } from './wait-for-passphrase-cipher-stream-provider-response';

/**
 * @type CipherStreamProviderListResponseResourcesInner
 * @export
 */
export type CipherStreamProviderListResponseResourcesInner = AmazonKeyManagementServiceCipherStreamProviderResponse | AmazonSecretsManagerCipherStreamProviderResponse | AzureKeyVaultCipherStreamProviderResponse | ConjurCipherStreamProviderResponse | DefaultCipherStreamProviderResponse | FileBasedCipherStreamProviderResponse | Pkcs11CipherStreamProviderResponse | ThirdPartyCipherStreamProviderResponse | VaultCipherStreamProviderResponse | WaitForPassphraseCipherStreamProviderResponse;


