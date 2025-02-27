/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnummockExternalServerSchemaUrn } from './enummock-external-server-schema-urn';

/**
 * 
 * @export
 * @interface MockExternalServerResponseAllOf
 */
export interface MockExternalServerResponseAllOf {
    /**
     * A description for this External Server
     * @type {string}
     * @memberof MockExternalServerResponseAllOf
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnummockExternalServerSchemaUrn>}
     * @memberof MockExternalServerResponseAllOf
     */
    'schemas'?: Array<EnummockExternalServerSchemaUrn>;
    /**
     * Name of the External Server
     * @type {string}
     * @memberof MockExternalServerResponseAllOf
     */
    'id'?: string;
    /**
     * Specifies the base DN stored in this mock resource.
     * @type {Array<string>}
     * @memberof MockExternalServerResponseAllOf
     */
    'baseDN'?: Array<string>;
}

