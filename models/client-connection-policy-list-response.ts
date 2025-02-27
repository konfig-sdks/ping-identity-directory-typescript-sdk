/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { ClientConnectionPolicyResponse } from './client-connection-policy-response';

/**
 * 
 * @export
 * @interface ClientConnectionPolicyListResponse
 */
export interface ClientConnectionPolicyListResponse {
    /**
     * 
     * @type {Array<string>}
     * @memberof ClientConnectionPolicyListResponse
     */
    'schemas'?: Array<string>;
    /**
     * 
     * @type {number}
     * @memberof ClientConnectionPolicyListResponse
     */
    'totalResults'?: number;
    /**
     * 
     * @type {Array<ClientConnectionPolicyResponse>}
     * @memberof ClientConnectionPolicyListResponse
     */
    'Resources'?: Array<ClientConnectionPolicyResponse>;
}

