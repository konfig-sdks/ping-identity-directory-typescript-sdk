/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumjmxConnectionHandlerSchemaUrn } from './enumjmx-connection-handler-schema-urn';
import { HttpConnectionHandlerResponseAllOf } from './http-connection-handler-response-all-of';
import { JmxConnectionHandlerShared } from './jmx-connection-handler-shared';
import { Meta } from './meta';
import { MetaMeta } from './meta-meta';
import { MetaUrnPingidentitySchemasConfigurationMessages20 } from './meta-urn-pingidentity-schemas-configuration-messages20';

/**
 * @type JmxConnectionHandlerResponse
 * @export
 */
export type JmxConnectionHandlerResponse = HttpConnectionHandlerResponseAllOf & JmxConnectionHandlerShared & Meta;


