/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { CustomSynchronizationProviderResponse } from './custom-synchronization-provider-response';
import { EnumcustomSynchronizationProviderSchemaUrn } from './enumcustom-synchronization-provider-schema-urn';
import { MetaMeta } from './meta-meta';
import { MetaUrnPingidentitySchemasConfigurationMessages20 } from './meta-urn-pingidentity-schemas-configuration-messages20';
import { ReplicationSynchronizationProviderResponse } from './replication-synchronization-provider-response';

/**
 * @type GetSynchronizationProvider200Response
 * @export
 */
export type GetSynchronizationProvider200Response = CustomSynchronizationProviderResponse | ReplicationSynchronizationProviderResponse;


