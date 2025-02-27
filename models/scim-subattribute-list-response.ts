/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { ScimSubattributeResponse } from './scim-subattribute-response';

/**
 * 
 * @export
 * @interface ScimSubattributeListResponse
 */
export interface ScimSubattributeListResponse {
    /**
     * 
     * @type {Array<string>}
     * @memberof ScimSubattributeListResponse
     */
    'schemas'?: Array<string>;
    /**
     * 
     * @type {number}
     * @memberof ScimSubattributeListResponse
     */
    'totalResults'?: number;
    /**
     * 
     * @type {Array<ScimSubattributeResponse>}
     * @memberof ScimSubattributeListResponse
     */
    'Resources'?: Array<ScimSubattributeResponse>;
}

