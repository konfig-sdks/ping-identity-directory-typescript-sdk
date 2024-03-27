/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"


/**
 * The mechanism to use to verify user credentials while ensuring that the ability to process other operations is not impacted by an alternate authorization identity.
 * @export
 * @enum {string}
 */
export type EnumexternalServerVerifyCredentialsMethodProp = 'separate-connections' | 'retain-identity-control' | 'bind-on-existing-connections'

