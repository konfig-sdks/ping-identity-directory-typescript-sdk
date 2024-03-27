/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumconnectionHandlerSslClientAuthPolicyProp } from './enumconnection-handler-ssl-client-auth-policy-prop';
import { EnumldifConnectionHandlerSchemaUrn } from './enumldif-connection-handler-schema-urn';
import { HttpConnectionHandlerResponse } from './http-connection-handler-response';
import { JmxConnectionHandlerResponse } from './jmx-connection-handler-response';
import { LdapConnectionHandlerResponse } from './ldap-connection-handler-response';
import { LdifConnectionHandlerResponse } from './ldif-connection-handler-response';
import { MetaMeta } from './meta-meta';
import { MetaUrnPingidentitySchemasConfigurationMessages20 } from './meta-urn-pingidentity-schemas-configuration-messages20';

/**
 * @type ConnectionHandlerListResponseResourcesInner
 * @export
 */
export type ConnectionHandlerListResponseResourcesInner = HttpConnectionHandlerResponse | JmxConnectionHandlerResponse | LdapConnectionHandlerResponse | LdifConnectionHandlerResponse;


