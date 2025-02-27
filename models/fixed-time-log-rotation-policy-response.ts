/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumfixedTimeLogRotationPolicySchemaUrn } from './enumfixed-time-log-rotation-policy-schema-urn';
import { FixedTimeLogRotationPolicyShared } from './fixed-time-log-rotation-policy-shared';
import { Meta } from './meta';
import { MetaMeta } from './meta-meta';
import { MetaUrnPingidentitySchemasConfigurationMessages20 } from './meta-urn-pingidentity-schemas-configuration-messages20';
import { TimeLimitLogRotationPolicyResponseAllOf } from './time-limit-log-rotation-policy-response-all-of';

/**
 * @type FixedTimeLogRotationPolicyResponse
 * @export
 */
export type FixedTimeLogRotationPolicyResponse = FixedTimeLogRotationPolicyShared & Meta & TimeLimitLogRotationPolicyResponseAllOf;


