/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { AddAppRoleVaultAuthenticationMethodRequest } from './add-app-role-vault-authentication-method-request';
import { AddStaticTokenVaultAuthenticationMethodRequest } from './add-static-token-vault-authentication-method-request';
import { AddUserPassVaultAuthenticationMethodRequest } from './add-user-pass-vault-authentication-method-request';
import { EnumuserPassVaultAuthenticationMethodSchemaUrn } from './enumuser-pass-vault-authentication-method-schema-urn';

/**
 * @type AddVaultAuthenticationMethodRequest
 * @export
 */
export type AddVaultAuthenticationMethodRequest = AddAppRoleVaultAuthenticationMethodRequest | AddStaticTokenVaultAuthenticationMethodRequest | AddUserPassVaultAuthenticationMethodRequest;


