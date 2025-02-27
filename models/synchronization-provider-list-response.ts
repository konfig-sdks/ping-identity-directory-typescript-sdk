/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { GetSynchronizationProvider200Response } from './get-synchronization-provider200-response';

/**
 * 
 * @export
 * @interface SynchronizationProviderListResponse
 */
export interface SynchronizationProviderListResponse {
    /**
     * 
     * @type {Array<string>}
     * @memberof SynchronizationProviderListResponse
     */
    'schemas'?: Array<string>;
    /**
     * 
     * @type {number}
     * @memberof SynchronizationProviderListResponse
     */
    'totalResults'?: number;
    /**
     * 
     * @type {Array<GetSynchronizationProvider200Response>}
     * @memberof SynchronizationProviderListResponse
     */
    'Resources'?: Array<GetSynchronizationProvider200Response>;
}

