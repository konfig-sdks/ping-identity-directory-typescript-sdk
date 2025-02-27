/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { BindAccessTokenValidatorResponse } from './bind-access-token-validator-response';
import { EnumaccessTokenValidatorAllowedAuthenticationTypeProp } from './enumaccess-token-validator-allowed-authentication-type-prop';
import { EnumaccessTokenValidatorAllowedContentEncryptionAlgorithmProp } from './enumaccess-token-validator-allowed-content-encryption-algorithm-prop';
import { EnumaccessTokenValidatorAllowedKeyEncryptionAlgorithmProp } from './enumaccess-token-validator-allowed-key-encryption-algorithm-prop';
import { EnumaccessTokenValidatorAllowedSigningAlgorithmProp } from './enumaccess-token-validator-allowed-signing-algorithm-prop';
import { EnumthirdPartyAccessTokenValidatorSchemaUrn } from './enumthird-party-access-token-validator-schema-urn';
import { ExternalApiGatewayAccessTokenValidatorResponse } from './external-api-gateway-access-token-validator-response';
import { JwtAccessTokenValidatorResponse } from './jwt-access-token-validator-response';
import { MetaMeta } from './meta-meta';
import { MetaUrnPingidentitySchemasConfigurationMessages20 } from './meta-urn-pingidentity-schemas-configuration-messages20';
import { MockAccessTokenValidatorResponse } from './mock-access-token-validator-response';
import { PingFederateAccessTokenValidatorResponse } from './ping-federate-access-token-validator-response';
import { ThirdPartyAccessTokenValidatorResponse } from './third-party-access-token-validator-response';

/**
 * @type AccessTokenValidatorListResponseResourcesInner
 * @export
 */
export type AccessTokenValidatorListResponseResourcesInner = BindAccessTokenValidatorResponse | ExternalApiGatewayAccessTokenValidatorResponse | JwtAccessTokenValidatorResponse | MockAccessTokenValidatorResponse | PingFederateAccessTokenValidatorResponse | ThirdPartyAccessTokenValidatorResponse;


