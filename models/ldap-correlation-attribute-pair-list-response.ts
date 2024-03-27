/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { LdapCorrelationAttributePairResponse } from './ldap-correlation-attribute-pair-response';

/**
 * 
 * @export
 * @interface LdapCorrelationAttributePairListResponse
 */
export interface LdapCorrelationAttributePairListResponse {
    /**
     * 
     * @type {Array<string>}
     * @memberof LdapCorrelationAttributePairListResponse
     */
    'schemas'?: Array<string>;
    /**
     * 
     * @type {number}
     * @memberof LdapCorrelationAttributePairListResponse
     */
    'totalResults'?: number;
    /**
     * 
     * @type {Array<LdapCorrelationAttributePairResponse>}
     * @memberof LdapCorrelationAttributePairListResponse
     */
    'Resources'?: Array<LdapCorrelationAttributePairResponse>;
}

