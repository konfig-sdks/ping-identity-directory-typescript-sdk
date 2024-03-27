/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumpassThroughScimResourceTypeSchemaUrn } from './enumpass-through-scim-resource-type-schema-urn';
import { EnumscimResourceTypeSchemaCheckingOptionProp } from './enumscim-resource-type-schema-checking-option-prop';
import { LdapMappingScimResourceTypeResponse } from './ldap-mapping-scim-resource-type-response';
import { LdapPassThroughScimResourceTypeResponse } from './ldap-pass-through-scim-resource-type-response';
import { MappingScimResourceTypeResponse } from './mapping-scim-resource-type-response';
import { MetaMeta } from './meta-meta';
import { MetaUrnPingidentitySchemasConfigurationMessages20 } from './meta-urn-pingidentity-schemas-configuration-messages20';
import { PassThroughScimResourceTypeResponse } from './pass-through-scim-resource-type-response';

/**
 * @type ScimResourceTypeListResponseResourcesInner
 * @export
 */
export type ScimResourceTypeListResponseResourcesInner = LdapMappingScimResourceTypeResponse | LdapPassThroughScimResourceTypeResponse | MappingScimResourceTypeResponse | PassThroughScimResourceTypeResponse;


