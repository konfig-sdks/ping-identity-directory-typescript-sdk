/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { AddAggregateIdentityMapperRequest } from './add-aggregate-identity-mapper-request';
import { AddDnIdentityMapperRequest } from './add-dn-identity-mapper-request';
import { AddExactMatchIdentityMapperRequest } from './add-exact-match-identity-mapper-request';
import { AddGroovyScriptedIdentityMapperRequest } from './add-groovy-scripted-identity-mapper-request';
import { AddRegularExpressionIdentityMapperRequest } from './add-regular-expression-identity-mapper-request';
import { AddThirdPartyIdentityMapperRequest } from './add-third-party-identity-mapper-request';
import { EnumthirdPartyIdentityMapperSchemaUrn } from './enumthird-party-identity-mapper-schema-urn';

/**
 * @type AddIdentityMapperRequest
 * @export
 */
export type AddIdentityMapperRequest = AddAggregateIdentityMapperRequest | AddDnIdentityMapperRequest | AddExactMatchIdentityMapperRequest | AddGroovyScriptedIdentityMapperRequest | AddRegularExpressionIdentityMapperRequest | AddThirdPartyIdentityMapperRequest;


