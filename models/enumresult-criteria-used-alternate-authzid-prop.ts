/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"


/**
 * Indicates whether operation results in which the associated operation used an authorization identity that is different from the authentication identity (e.g., as the result of using a proxied authorization control) should be included in this Simple Result Criteria. If no value is provided, then whether an operation used an alternate authorization identity will not be considered when determining whether it matches this Simple Result Criteria.
 * @export
 * @enum {string}
 */
export type EnumresultCriteriaUsedAlternateAuthzidProp = 'required' | 'prohibited' | 'optional'

