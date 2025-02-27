/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { ReplicationDomainResponse } from './replication-domain-response';

/**
 * 
 * @export
 * @interface ReplicationDomainListResponse
 */
export interface ReplicationDomainListResponse {
    /**
     * 
     * @type {Array<string>}
     * @memberof ReplicationDomainListResponse
     */
    'schemas'?: Array<string>;
    /**
     * 
     * @type {number}
     * @memberof ReplicationDomainListResponse
     */
    'totalResults'?: number;
    /**
     * 
     * @type {Array<ReplicationDomainResponse>}
     * @memberof ReplicationDomainListResponse
     */
    'Resources'?: Array<ReplicationDomainResponse>;
}

