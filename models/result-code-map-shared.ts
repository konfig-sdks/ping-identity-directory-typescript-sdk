/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumresultCodeMapSchemaUrn } from './enumresult-code-map-schema-urn';

/**
 * 
 * @export
 * @interface ResultCodeMapShared
 */
export interface ResultCodeMapShared {
    /**
     * A description for this Result Code Map
     * @type {string}
     * @memberof ResultCodeMapShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumresultCodeMapSchemaUrn>}
     * @memberof ResultCodeMapShared
     */
    'schemas'?: Array<EnumresultCodeMapSchemaUrn>;
    /**
     * Specifies the result code that should be returned if a bind attempt fails because the user\'s account is locked as a result of too many failed authentication attempts.
     * @type {number}
     * @memberof ResultCodeMapShared
     */
    'bindAccountLockedResultCode'?: number;
    /**
     * Specifies the result code that should be returned if a bind attempt fails because the target user entry does not exist in the server.
     * @type {number}
     * @memberof ResultCodeMapShared
     */
    'bindMissingUserResultCode'?: number;
    /**
     * Specifies the result code that should be returned if a password-based bind attempt fails because the target user entry does not have a password.
     * @type {number}
     * @memberof ResultCodeMapShared
     */
    'bindMissingPasswordResultCode'?: number;
    /**
     * Specifies the result code that should be returned if a generic error occurs within the server.
     * @type {number}
     * @memberof ResultCodeMapShared
     */
    'serverErrorResultCode'?: number;
}

