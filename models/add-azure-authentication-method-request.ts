/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { AddClientSecretAzureAuthenticationMethodRequest } from './add-client-secret-azure-authentication-method-request';
import { AddDefaultAzureAuthenticationMethodRequest } from './add-default-azure-authentication-method-request';
import { AddUsernamePasswordAzureAuthenticationMethodRequest } from './add-username-password-azure-authentication-method-request';
import { EnumusernamePasswordAzureAuthenticationMethodSchemaUrn } from './enumusername-password-azure-authentication-method-schema-urn';

/**
 * @type AddAzureAuthenticationMethodRequest
 * @export
 */
export type AddAzureAuthenticationMethodRequest = AddClientSecretAzureAuthenticationMethodRequest | AddDefaultAzureAuthenticationMethodRequest | AddUsernamePasswordAzureAuthenticationMethodRequest;


