/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { LogFieldBehaviorListResponseResourcesInner } from './log-field-behavior-list-response-resources-inner';

/**
 * 
 * @export
 * @interface LogFieldBehaviorListResponse
 */
export interface LogFieldBehaviorListResponse {
    /**
     * 
     * @type {Array<string>}
     * @memberof LogFieldBehaviorListResponse
     */
    'schemas'?: Array<string>;
    /**
     * 
     * @type {number}
     * @memberof LogFieldBehaviorListResponse
     */
    'totalResults'?: number;
    /**
     * 
     * @type {Array<LogFieldBehaviorListResponseResourcesInner>}
     * @memberof LogFieldBehaviorListResponse
     */
    'Resources'?: Array<LogFieldBehaviorListResponseResourcesInner>;
}

