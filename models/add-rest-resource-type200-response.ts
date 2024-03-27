/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumgroupRestResourceTypeSchemaUrn } from './enumgroup-rest-resource-type-schema-urn';
import { GenericRestResourceTypeResponse } from './generic-rest-resource-type-response';
import { GroupRestResourceTypeResponse } from './group-rest-resource-type-response';
import { MetaMeta } from './meta-meta';
import { MetaUrnPingidentitySchemasConfigurationMessages20 } from './meta-urn-pingidentity-schemas-configuration-messages20';
import { UserRestResourceTypeResponse } from './user-rest-resource-type-response';

/**
 * @type AddRestResourceType200Response
 * @export
 */
export type AddRestResourceType200Response = GenericRestResourceTypeResponse | GroupRestResourceTypeResponse | UserRestResourceTypeResponse;


