/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { SaslMechanismHandlerListResponseResourcesInner } from './sasl-mechanism-handler-list-response-resources-inner';

/**
 * 
 * @export
 * @interface SaslMechanismHandlerListResponse
 */
export interface SaslMechanismHandlerListResponse {
    /**
     * 
     * @type {Array<string>}
     * @memberof SaslMechanismHandlerListResponse
     */
    'schemas'?: Array<string>;
    /**
     * 
     * @type {number}
     * @memberof SaslMechanismHandlerListResponse
     */
    'totalResults'?: number;
    /**
     * 
     * @type {Array<SaslMechanismHandlerListResponseResourcesInner>}
     * @memberof SaslMechanismHandlerListResponse
     */
    'Resources'?: Array<SaslMechanismHandlerListResponseResourcesInner>;
}

