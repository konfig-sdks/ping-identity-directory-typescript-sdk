/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { ConjurExternalServerShared } from './conjur-external-server-shared';
import { EnumconjurExternalServerSchemaUrn } from './enumconjur-external-server-schema-urn';
import { Meta } from './meta';
import { MetaMeta } from './meta-meta';
import { MetaUrnPingidentitySchemasConfigurationMessages20 } from './meta-urn-pingidentity-schemas-configuration-messages20';
import { NokiaDsExternalServerResponseAllOf } from './nokia-ds-external-server-response-all-of';

/**
 * @type ConjurExternalServerResponse
 * @export
 */
export type ConjurExternalServerResponse = ConjurExternalServerShared & Meta & NokiaDsExternalServerResponseAllOf;


