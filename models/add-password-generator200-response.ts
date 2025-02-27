/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumthirdPartyPasswordGeneratorSchemaUrn } from './enumthird-party-password-generator-schema-urn';
import { GroovyScriptedPasswordGeneratorResponse } from './groovy-scripted-password-generator-response';
import { MetaMeta } from './meta-meta';
import { MetaUrnPingidentitySchemasConfigurationMessages20 } from './meta-urn-pingidentity-schemas-configuration-messages20';
import { PassphrasePasswordGeneratorResponse } from './passphrase-password-generator-response';
import { RandomPasswordGeneratorResponse } from './random-password-generator-response';
import { ThirdPartyPasswordGeneratorResponse } from './third-party-password-generator-response';

/**
 * @type AddPasswordGenerator200Response
 * @export
 */
export type AddPasswordGenerator200Response = GroovyScriptedPasswordGeneratorResponse | PassphrasePasswordGeneratorResponse | RandomPasswordGeneratorResponse | ThirdPartyPasswordGeneratorResponse;


