/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"


/**
 * Indicates whether to validate the OAuth access token in addition to the OpenID Connect ID token in OAUTHBEARER bind requests that contain both types of tokens.
 * @export
 * @enum {string}
 */
export type EnumsaslMechanismHandlerValidateAccessTokenWhenIDTokenIsAlsoProvidedProp = 'validate-only-the-id-token' | 'validate-both-tokens-but-only-map-the-id-token' | 'validate-and-map-both-tokens'

