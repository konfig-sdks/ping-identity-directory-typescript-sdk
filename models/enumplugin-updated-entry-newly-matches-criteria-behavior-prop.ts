/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"


/**
 * The behavior to exhibit for modify or modify DN operations that update an entry that previously did not satisfy either the base DN or filter criteria, but now do satisfy that criteria.
 * @export
 * @enum {string}
 */
export type EnumpluginUpdatedEntryNewlyMatchesCriteriaBehaviorProp = 'preserve-existing-values-without-composing-new-values' | 'preserve-existing-values-or-compose-new-values' | 'preserve-existing-values-and-compose-new-values' | 'compose-new-values-without-preserving-existing-values'

