/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"


/**
 * Specifies the cache mode that should be used when accessing the records in the dn2uri database, which provides a mapping between a normalized entry DN and a set of referral URLs contained in the associated smart referral entry.
 * @export
 * @enum {string}
 */
export type EnumbackendDn2uriCacheModeProp = 'cache-keys-and-values' | 'cache-keys-only' | 'no-caching' | 'keep-hot' | 'default' | 'make-cold' | 'evict-leaf-immediately' | 'evict-bin-immediately'

