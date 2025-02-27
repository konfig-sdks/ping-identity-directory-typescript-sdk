/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { MonitorProviderListResponseResourcesInner } from './monitor-provider-list-response-resources-inner';

/**
 * 
 * @export
 * @interface MonitorProviderListResponse
 */
export interface MonitorProviderListResponse {
    /**
     * 
     * @type {Array<string>}
     * @memberof MonitorProviderListResponse
     */
    'schemas'?: Array<string>;
    /**
     * 
     * @type {number}
     * @memberof MonitorProviderListResponse
     */
    'totalResults'?: number;
    /**
     * 
     * @type {Array<MonitorProviderListResponseResourcesInner>}
     * @memberof MonitorProviderListResponse
     */
    'Resources'?: Array<MonitorProviderListResponseResourcesInner>;
}

