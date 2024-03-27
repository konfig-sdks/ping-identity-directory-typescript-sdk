/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"


/**
 * Indicates whether the time required to process the operation should be taken into consideration when determining whether to include the operation in this Simple Result Criteria. If the processing time should be taken into account, then the \"processing-time-value\" property should contain the boundary value.
 * @export
 * @enum {string}
 */
export type EnumresultCriteriaProcessingTimeCriteriaProp = 'any' | 'less-than-or-equal-to' | 'greater-than-or-equal-to'

