/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { SensitiveAttributeResponse } from './sensitive-attribute-response';

/**
 * 
 * @export
 * @interface SensitiveAttributeListResponse
 */
export interface SensitiveAttributeListResponse {
    /**
     * 
     * @type {Array<string>}
     * @memberof SensitiveAttributeListResponse
     */
    'schemas'?: Array<string>;
    /**
     * 
     * @type {number}
     * @memberof SensitiveAttributeListResponse
     */
    'totalResults'?: number;
    /**
     * 
     * @type {Array<SensitiveAttributeResponse>}
     * @memberof SensitiveAttributeListResponse
     */
    'Resources'?: Array<SensitiveAttributeResponse>;
}

