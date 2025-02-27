/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { AddOauthBearerSaslMechanismHandlerRequest } from './add-oauth-bearer-sasl-mechanism-handler-request';
import { AddThirdPartySaslMechanismHandlerRequest } from './add-third-party-sasl-mechanism-handler-request';
import { AddUnboundidDeliveredOtpSaslMechanismHandlerRequest } from './add-unboundid-delivered-otp-sasl-mechanism-handler-request';
import { AddUnboundidMsChapV2SaslMechanismHandlerRequest } from './add-unboundid-ms-chap-v2-sasl-mechanism-handler-request';
import { EnumsaslMechanismHandlerValidateAccessTokenWhenIDTokenIsAlsoProvidedProp } from './enumsasl-mechanism-handler-validate-access-token-when-idtoken-is-also-provided-prop';
import { EnumthirdPartySaslMechanismHandlerSchemaUrn } from './enumthird-party-sasl-mechanism-handler-schema-urn';

/**
 * @type AddSaslMechanismHandlerRequest
 * @export
 */
export type AddSaslMechanismHandlerRequest = AddOauthBearerSaslMechanismHandlerRequest | AddThirdPartySaslMechanismHandlerRequest | AddUnboundidDeliveredOtpSaslMechanismHandlerRequest | AddUnboundidMsChapV2SaslMechanismHandlerRequest;


