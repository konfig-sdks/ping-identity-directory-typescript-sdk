/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { AggregateConnectionCriteriaResponse } from './aggregate-connection-criteria-response';
import { EnumconnectionCriteriaAllIncludedUserPrivilegeProp } from './enumconnection-criteria-all-included-user-privilege-prop';
import { EnumconnectionCriteriaAnyIncludedUserPrivilegeProp } from './enumconnection-criteria-any-included-user-privilege-prop';
import { EnumconnectionCriteriaAuthenticationSecurityLevelProp } from './enumconnection-criteria-authentication-security-level-prop';
import { EnumconnectionCriteriaCommunicationSecurityLevelProp } from './enumconnection-criteria-communication-security-level-prop';
import { EnumconnectionCriteriaNoneIncludedUserPrivilegeProp } from './enumconnection-criteria-none-included-user-privilege-prop';
import { EnumconnectionCriteriaNotAllIncludedUserPrivilegeProp } from './enumconnection-criteria-not-all-included-user-privilege-prop';
import { EnumconnectionCriteriaUserAuthTypeProp } from './enumconnection-criteria-user-auth-type-prop';
import { EnumthirdPartyConnectionCriteriaSchemaUrn } from './enumthird-party-connection-criteria-schema-urn';
import { MetaMeta } from './meta-meta';
import { MetaUrnPingidentitySchemasConfigurationMessages20 } from './meta-urn-pingidentity-schemas-configuration-messages20';
import { SimpleConnectionCriteriaResponse } from './simple-connection-criteria-response';
import { ThirdPartyConnectionCriteriaResponse } from './third-party-connection-criteria-response';

/**
 * @type AddConnectionCriteria200Response
 * @export
 */
export type AddConnectionCriteria200Response = AggregateConnectionCriteriaResponse | SimpleConnectionCriteriaResponse | ThirdPartyConnectionCriteriaResponse;


