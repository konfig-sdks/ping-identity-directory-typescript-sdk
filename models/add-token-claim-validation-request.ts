/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { AddBooleanTokenClaimValidationRequest } from './add-boolean-token-claim-validation-request';
import { AddStringArrayTokenClaimValidationRequest } from './add-string-array-token-claim-validation-request';
import { AddStringTokenClaimValidationRequest } from './add-string-token-claim-validation-request';
import { EnumstringTokenClaimValidationSchemaUrn } from './enumstring-token-claim-validation-schema-urn';
import { EnumtokenClaimValidationRequiredValueProp } from './enumtoken-claim-validation-required-value-prop';

/**
 * @type AddTokenClaimValidationRequest
 * @export
 */
export type AddTokenClaimValidationRequest = AddBooleanTokenClaimValidationRequest | AddStringArrayTokenClaimValidationRequest | AddStringTokenClaimValidationRequest;


