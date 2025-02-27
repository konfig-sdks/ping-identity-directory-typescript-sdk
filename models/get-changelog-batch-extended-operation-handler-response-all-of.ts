/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumgetChangelogBatchExtendedOperationHandlerSchemaUrn } from './enumget-changelog-batch-extended-operation-handler-schema-urn';

/**
 * 
 * @export
 * @interface GetChangelogBatchExtendedOperationHandlerResponseAllOf
 */
export interface GetChangelogBatchExtendedOperationHandlerResponseAllOf {
    /**
     * A description for this Extended Operation Handler
     * @type {string}
     * @memberof GetChangelogBatchExtendedOperationHandlerResponseAllOf
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumgetChangelogBatchExtendedOperationHandlerSchemaUrn>}
     * @memberof GetChangelogBatchExtendedOperationHandlerResponseAllOf
     */
    'schemas'?: Array<EnumgetChangelogBatchExtendedOperationHandlerSchemaUrn>;
    /**
     * Name of the Extended Operation Handler
     * @type {string}
     * @memberof GetChangelogBatchExtendedOperationHandlerResponseAllOf
     */
    'id'?: string;
    /**
     * Indicates whether the Extended Operation Handler is enabled (that is, whether the types of extended operations are allowed in the server).
     * @type {boolean}
     * @memberof GetChangelogBatchExtendedOperationHandlerResponseAllOf
     */
    'enabled'?: boolean;
}

