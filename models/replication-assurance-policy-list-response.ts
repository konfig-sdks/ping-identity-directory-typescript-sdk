/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { ReplicationAssurancePolicyResponse } from './replication-assurance-policy-response';

/**
 * 
 * @export
 * @interface ReplicationAssurancePolicyListResponse
 */
export interface ReplicationAssurancePolicyListResponse {
    /**
     * 
     * @type {Array<string>}
     * @memberof ReplicationAssurancePolicyListResponse
     */
    'schemas'?: Array<string>;
    /**
     * 
     * @type {number}
     * @memberof ReplicationAssurancePolicyListResponse
     */
    'totalResults'?: number;
    /**
     * 
     * @type {Array<ReplicationAssurancePolicyResponse>}
     * @memberof ReplicationAssurancePolicyListResponse
     */
    'Resources'?: Array<ReplicationAssurancePolicyResponse>;
}

