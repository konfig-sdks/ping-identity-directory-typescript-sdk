/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"


/**
 * Specifies the names of any request controls that should be allowed by the Directory REST API. Any request that contains a critical control not in this list will be rejected. Any non-critical request control which is not supported by the Directory REST API will be removed from the request.
 * @export
 * @enum {string}
 */
export type EnumhttpServletExtensionAllowedControlProp = 'access-log-field' | 'assertion' | 'assured-replication' | 'exclude-branch' | 'generate-password' | 'get-effective-rights' | 'get-password-policy-state-issues' | 'get-recent-login-history' | 'get-user-resource-limits' | 'ignore-no-user-modification' | 'intermediate-client' | 'join' | 'manage-dsa-it' | 'matched-values' | 'matching-entry-count' | 'name-with-entryuuid' | 'no-op' | 'operation-purpose' | 'password-update-behavior' | 'password-validation-details' | 'permissive-modify' | 'permit-unindexed-search' | 'post-read' | 'pre-read' | 'proxied-authorization-v1' | 'proxied-authorization-v2' | 'purge-password' | 'real-attributes-only' | 'reject-unindexed-search' | 'retire-password' | 'suppress-referential-integrity' | 'uniqueness' | 'virtual-attributes-only'

