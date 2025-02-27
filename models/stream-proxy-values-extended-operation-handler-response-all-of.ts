/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumstreamProxyValuesExtendedOperationHandlerSchemaUrn } from './enumstream-proxy-values-extended-operation-handler-schema-urn';

/**
 * 
 * @export
 * @interface StreamProxyValuesExtendedOperationHandlerResponseAllOf
 */
export interface StreamProxyValuesExtendedOperationHandlerResponseAllOf {
    /**
     * A description for this Extended Operation Handler
     * @type {string}
     * @memberof StreamProxyValuesExtendedOperationHandlerResponseAllOf
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumstreamProxyValuesExtendedOperationHandlerSchemaUrn>}
     * @memberof StreamProxyValuesExtendedOperationHandlerResponseAllOf
     */
    'schemas'?: Array<EnumstreamProxyValuesExtendedOperationHandlerSchemaUrn>;
    /**
     * Name of the Extended Operation Handler
     * @type {string}
     * @memberof StreamProxyValuesExtendedOperationHandlerResponseAllOf
     */
    'id'?: string;
    /**
     * The maximum number of values to include per response when responding to a stream values extended request, when the client does not specify a value.
     * @type {number}
     * @memberof StreamProxyValuesExtendedOperationHandlerResponseAllOf
     */
    'valuesPerStreamResponse'?: number;
    /**
     * Indicates whether the Extended Operation Handler is enabled (that is, whether the types of extended operations are allowed in the server).
     * @type {boolean}
     * @memberof StreamProxyValuesExtendedOperationHandlerResponseAllOf
     */
    'enabled'?: boolean;
}

