/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"


/**
 * Specifies the assurance level used to replicate to remote servers. A remote server is defined as one with a different value for the location setting in the global configuration.
 * @export
 * @enum {string}
 */
export type EnumreplicationAssurancePolicyRemoteLevelProp = 'none' | 'received-any-remote-location' | 'received-all-remote-locations' | 'processed-all-remote-servers'

