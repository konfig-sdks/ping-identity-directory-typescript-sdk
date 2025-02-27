/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { AddLogRotationPolicy200Response } from './add-log-rotation-policy200-response';

/**
 * 
 * @export
 * @interface LogRotationPolicyListResponse
 */
export interface LogRotationPolicyListResponse {
    /**
     * 
     * @type {Array<string>}
     * @memberof LogRotationPolicyListResponse
     */
    'schemas'?: Array<string>;
    /**
     * 
     * @type {number}
     * @memberof LogRotationPolicyListResponse
     */
    'totalResults'?: number;
    /**
     * 
     * @type {Array<AddLogRotationPolicy200Response>}
     * @memberof LogRotationPolicyListResponse
     */
    'Resources'?: Array<AddLogRotationPolicy200Response>;
}

