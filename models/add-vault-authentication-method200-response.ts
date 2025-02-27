/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { AppRoleVaultAuthenticationMethodResponse } from './app-role-vault-authentication-method-response';
import { EnumuserPassVaultAuthenticationMethodSchemaUrn } from './enumuser-pass-vault-authentication-method-schema-urn';
import { MetaMeta } from './meta-meta';
import { MetaUrnPingidentitySchemasConfigurationMessages20 } from './meta-urn-pingidentity-schemas-configuration-messages20';
import { StaticTokenVaultAuthenticationMethodResponse } from './static-token-vault-authentication-method-response';
import { UserPassVaultAuthenticationMethodResponse } from './user-pass-vault-authentication-method-response';

/**
 * @type AddVaultAuthenticationMethod200Response
 * @export
 */
export type AddVaultAuthenticationMethod200Response = AppRoleVaultAuthenticationMethodResponse | StaticTokenVaultAuthenticationMethodResponse | UserPassVaultAuthenticationMethodResponse;


