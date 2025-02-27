/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { AddNokiaDsExternalServerRequestAllOf } from './add-nokia-ds-external-server-request-all-of';
import { EnumexternalServerSmtpSecurityProp } from './enumexternal-server-smtp-security-prop';
import { EnumsmtpExternalServerSchemaUrn } from './enumsmtp-external-server-schema-urn';
import { SmtpExternalServerShared } from './smtp-external-server-shared';

/**
 * @type AddSmtpExternalServerRequest
 * @export
 */
export type AddSmtpExternalServerRequest = AddNokiaDsExternalServerRequestAllOf & SmtpExternalServerShared;


