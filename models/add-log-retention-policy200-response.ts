/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumsizeLimitLogRetentionPolicySchemaUrn } from './enumsize-limit-log-retention-policy-schema-urn';
import { FileCountLogRetentionPolicyResponse } from './file-count-log-retention-policy-response';
import { FreeDiskSpaceLogRetentionPolicyResponse } from './free-disk-space-log-retention-policy-response';
import { MetaMeta } from './meta-meta';
import { MetaUrnPingidentitySchemasConfigurationMessages20 } from './meta-urn-pingidentity-schemas-configuration-messages20';
import { NeverDeleteLogRetentionPolicyResponse } from './never-delete-log-retention-policy-response';
import { SizeLimitLogRetentionPolicyResponse } from './size-limit-log-retention-policy-response';
import { TimeLimitLogRetentionPolicyResponse } from './time-limit-log-retention-policy-response';

/**
 * @type AddLogRetentionPolicy200Response
 * @export
 */
export type AddLogRetentionPolicy200Response = FileCountLogRetentionPolicyResponse | FreeDiskSpaceLogRetentionPolicyResponse | NeverDeleteLogRetentionPolicyResponse | SizeLimitLogRetentionPolicyResponse | TimeLimitLogRetentionPolicyResponse;


