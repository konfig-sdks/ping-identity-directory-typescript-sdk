/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumidTokenValidatorAllowedSigningAlgorithmProp } from './enumid-token-validator-allowed-signing-algorithm-prop';
import { EnumopenidConnectIdTokenValidatorSchemaUrn } from './enumopenid-connect-id-token-validator-schema-urn';
import { MetaMeta } from './meta-meta';
import { MetaUrnPingidentitySchemasConfigurationMessages20 } from './meta-urn-pingidentity-schemas-configuration-messages20';
import { OpenidConnectIdTokenValidatorResponse } from './openid-connect-id-token-validator-response';
import { PingOneIdTokenValidatorResponse } from './ping-one-id-token-validator-response';

/**
 * @type AddIdTokenValidator200Response
 * @export
 */
export type AddIdTokenValidator200Response = OpenidConnectIdTokenValidatorResponse | PingOneIdTokenValidatorResponse;


