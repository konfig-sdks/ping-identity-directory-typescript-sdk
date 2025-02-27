/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { ResultCodeMapResponse } from './result-code-map-response';

/**
 * 
 * @export
 * @interface ResultCodeMapListResponse
 */
export interface ResultCodeMapListResponse {
    /**
     * 
     * @type {Array<string>}
     * @memberof ResultCodeMapListResponse
     */
    'schemas'?: Array<string>;
    /**
     * 
     * @type {number}
     * @memberof ResultCodeMapListResponse
     */
    'totalResults'?: number;
    /**
     * 
     * @type {Array<ResultCodeMapResponse>}
     * @memberof ResultCodeMapListResponse
     */
    'Resources'?: Array<ResultCodeMapResponse>;
}

