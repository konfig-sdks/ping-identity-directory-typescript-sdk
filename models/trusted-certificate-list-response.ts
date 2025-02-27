/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { TrustedCertificateResponse } from './trusted-certificate-response';

/**
 * 
 * @export
 * @interface TrustedCertificateListResponse
 */
export interface TrustedCertificateListResponse {
    /**
     * 
     * @type {Array<string>}
     * @memberof TrustedCertificateListResponse
     */
    'schemas'?: Array<string>;
    /**
     * 
     * @type {number}
     * @memberof TrustedCertificateListResponse
     */
    'totalResults'?: number;
    /**
     * 
     * @type {Array<TrustedCertificateResponse>}
     * @memberof TrustedCertificateListResponse
     */
    'Resources'?: Array<TrustedCertificateResponse>;
}

