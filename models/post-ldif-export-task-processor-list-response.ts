/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { AddPostLdifExportTaskProcessor200Response } from './add-post-ldif-export-task-processor200-response';

/**
 * 
 * @export
 * @interface PostLdifExportTaskProcessorListResponse
 */
export interface PostLdifExportTaskProcessorListResponse {
    /**
     * 
     * @type {Array<string>}
     * @memberof PostLdifExportTaskProcessorListResponse
     */
    'schemas'?: Array<string>;
    /**
     * 
     * @type {number}
     * @memberof PostLdifExportTaskProcessorListResponse
     */
    'totalResults'?: number;
    /**
     * 
     * @type {Array<AddPostLdifExportTaskProcessor200Response>}
     * @memberof PostLdifExportTaskProcessorListResponse
     */
    'Resources'?: Array<AddPostLdifExportTaskProcessor200Response>;
}

