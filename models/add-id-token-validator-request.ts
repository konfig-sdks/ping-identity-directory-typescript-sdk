/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { AddOpenidConnectIdTokenValidatorRequest } from './add-openid-connect-id-token-validator-request';
import { AddPingOneIdTokenValidatorRequest } from './add-ping-one-id-token-validator-request';
import { EnumidTokenValidatorAllowedSigningAlgorithmProp } from './enumid-token-validator-allowed-signing-algorithm-prop';
import { EnumopenidConnectIdTokenValidatorSchemaUrn } from './enumopenid-connect-id-token-validator-schema-urn';

/**
 * @type AddIdTokenValidatorRequest
 * @export
 */
export type AddIdTokenValidatorRequest = AddOpenidConnectIdTokenValidatorRequest | AddPingOneIdTokenValidatorRequest;


