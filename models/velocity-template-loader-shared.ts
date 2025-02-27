/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumvelocityTemplateLoaderSchemaUrn } from './enumvelocity-template-loader-schema-urn';

/**
 * 
 * @export
 * @interface VelocityTemplateLoaderShared
 */
export interface VelocityTemplateLoaderShared {
    /**
     * 
     * @type {Array<EnumvelocityTemplateLoaderSchemaUrn>}
     * @memberof VelocityTemplateLoaderShared
     */
    'schemas'?: Array<EnumvelocityTemplateLoaderSchemaUrn>;
    /**
     * Indicates whether this Velocity Template Loader is enabled.
     * @type {boolean}
     * @memberof VelocityTemplateLoaderShared
     */
    'enabled'?: boolean;
    /**
     * This property determines the evaluation order for determining the correct Velocity Template Loader to load a template for generating content for a particular request.
     * @type {number}
     * @memberof VelocityTemplateLoaderShared
     */
    'evaluationOrderIndex'?: number;
    /**
     * Specifies a media type for matching Accept request-header values.
     * @type {string}
     * @memberof VelocityTemplateLoaderShared
     */
    'mimeTypeMatcher': string;
    /**
     * Specifies a the value that will be used in the response\'s Content-Type header that indicates the type of content to return.
     * @type {string}
     * @memberof VelocityTemplateLoaderShared
     */
    'mimeType'?: string;
    /**
     * Specifies the suffix to append to the requested resource name when searching for the template file with which to form a response.
     * @type {string}
     * @memberof VelocityTemplateLoaderShared
     */
    'templateSuffix'?: string;
    /**
     * Specifies the directory in which to search for the template files.
     * @type {string}
     * @memberof VelocityTemplateLoaderShared
     */
    'templateDirectory'?: string;
}

