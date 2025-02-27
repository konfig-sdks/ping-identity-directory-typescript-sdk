/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { AddGauge200Response } from './add-gauge200-response';

/**
 * 
 * @export
 * @interface GaugeListResponse
 */
export interface GaugeListResponse {
    /**
     * 
     * @type {Array<string>}
     * @memberof GaugeListResponse
     */
    'schemas'?: Array<string>;
    /**
     * 
     * @type {number}
     * @memberof GaugeListResponse
     */
    'totalResults'?: number;
    /**
     * 
     * @type {Array<AddGauge200Response>}
     * @memberof GaugeListResponse
     */
    'Resources'?: Array<AddGauge200Response>;
}

