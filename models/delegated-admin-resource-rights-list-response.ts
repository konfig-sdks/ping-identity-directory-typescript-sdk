/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { DelegatedAdminResourceRightsResponse } from './delegated-admin-resource-rights-response';

/**
 * 
 * @export
 * @interface DelegatedAdminResourceRightsListResponse
 */
export interface DelegatedAdminResourceRightsListResponse {
    /**
     * 
     * @type {Array<string>}
     * @memberof DelegatedAdminResourceRightsListResponse
     */
    'schemas'?: Array<string>;
    /**
     * 
     * @type {number}
     * @memberof DelegatedAdminResourceRightsListResponse
     */
    'totalResults'?: number;
    /**
     * 
     * @type {Array<DelegatedAdminResourceRightsResponse>}
     * @memberof DelegatedAdminResourceRightsListResponse
     */
    'Resources'?: Array<DelegatedAdminResourceRightsResponse>;
}

