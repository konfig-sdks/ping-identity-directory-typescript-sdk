/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { AddSearchEntryCriteria200Response } from './add-search-entry-criteria200-response';

/**
 * 
 * @export
 * @interface SearchEntryCriteriaListResponse
 */
export interface SearchEntryCriteriaListResponse {
    /**
     * 
     * @type {Array<string>}
     * @memberof SearchEntryCriteriaListResponse
     */
    'schemas'?: Array<string>;
    /**
     * 
     * @type {number}
     * @memberof SearchEntryCriteriaListResponse
     */
    'totalResults'?: number;
    /**
     * 
     * @type {Array<AddSearchEntryCriteria200Response>}
     * @memberof SearchEntryCriteriaListResponse
     */
    'Resources'?: Array<AddSearchEntryCriteria200Response>;
}

