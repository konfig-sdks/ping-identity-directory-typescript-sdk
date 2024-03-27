/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumaccessTokenValidatorAllowedContentEncryptionAlgorithmProp } from './enumaccess-token-validator-allowed-content-encryption-algorithm-prop';
import { EnumaccessTokenValidatorAllowedKeyEncryptionAlgorithmProp } from './enumaccess-token-validator-allowed-key-encryption-algorithm-prop';
import { EnumaccessTokenValidatorAllowedSigningAlgorithmProp } from './enumaccess-token-validator-allowed-signing-algorithm-prop';
import { EnumthirdPartyAccessTokenValidatorSchemaUrn } from './enumthird-party-access-token-validator-schema-urn';
import { JwtAccessTokenValidatorResponse } from './jwt-access-token-validator-response';
import { MetaMeta } from './meta-meta';
import { MetaUrnPingidentitySchemasConfigurationMessages20 } from './meta-urn-pingidentity-schemas-configuration-messages20';
import { MockAccessTokenValidatorResponse } from './mock-access-token-validator-response';
import { PingFederateAccessTokenValidatorResponse } from './ping-federate-access-token-validator-response';
import { ThirdPartyAccessTokenValidatorResponse } from './third-party-access-token-validator-response';

/**
 * @type AddAccessTokenValidator200Response
 * @export
 */
export type AddAccessTokenValidator200Response = JwtAccessTokenValidatorResponse | MockAccessTokenValidatorResponse | PingFederateAccessTokenValidatorResponse | ThirdPartyAccessTokenValidatorResponse;


