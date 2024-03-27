/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumthirdPartyPasswordGeneratorSchemaUrn } from './enumthird-party-password-generator-schema-urn';
import { Meta } from './meta';
import { MetaMeta } from './meta-meta';
import { MetaUrnPingidentitySchemasConfigurationMessages20 } from './meta-urn-pingidentity-schemas-configuration-messages20';
import { RandomPasswordGeneratorResponseAllOf } from './random-password-generator-response-all-of';
import { ThirdPartyPasswordGeneratorShared } from './third-party-password-generator-shared';

/**
 * @type ThirdPartyPasswordGeneratorResponse
 * @export
 */
export type ThirdPartyPasswordGeneratorResponse = Meta & RandomPasswordGeneratorResponseAllOf & ThirdPartyPasswordGeneratorShared;


