/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { DnMapResponse } from './dn-map-response';

/**
 * 
 * @export
 * @interface DnMapListResponse
 */
export interface DnMapListResponse {
    /**
     * 
     * @type {Array<string>}
     * @memberof DnMapListResponse
     */
    'schemas'?: Array<string>;
    /**
     * 
     * @type {number}
     * @memberof DnMapListResponse
     */
    'totalResults'?: number;
    /**
     * 
     * @type {Array<DnMapResponse>}
     * @memberof DnMapListResponse
     */
    'Resources'?: Array<DnMapResponse>;
}

