/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"


/**
 * Specifies the method that should be used to prime caches with data for this backend.
 * @export
 * @enum {string}
 */
export type EnumbackendPrimeMethodProp = 'none' | 'preload' | 'preload-internal-nodes-only' | 'cursor-across-indexes' | 'prime-to-filesystem-cache' | 'prime-to-filesystem-cache-non-sequential'

