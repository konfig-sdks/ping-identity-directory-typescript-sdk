/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"


/**
 * Specifies the action which should be taken for any database that experiences an unrecoverable error. Action applies to local database backends and the replication recent changes database.
 * @export
 * @enum {string}
 */
export type EnumglobalConfigurationUnrecoverableDatabaseErrorModeProp = 'enter-lockdown-mode' | 'raise-unavailable-alarm' | 'initiate-server-shutdown'

