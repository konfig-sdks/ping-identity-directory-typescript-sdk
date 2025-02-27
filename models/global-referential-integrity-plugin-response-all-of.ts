/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumglobalReferentialIntegrityPluginSchemaUrn } from './enumglobal-referential-integrity-plugin-schema-urn';

/**
 * 
 * @export
 * @interface GlobalReferentialIntegrityPluginResponseAllOf
 */
export interface GlobalReferentialIntegrityPluginResponseAllOf {
    /**
     * A description for this Plugin
     * @type {string}
     * @memberof GlobalReferentialIntegrityPluginResponseAllOf
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumglobalReferentialIntegrityPluginSchemaUrn>}
     * @memberof GlobalReferentialIntegrityPluginResponseAllOf
     */
    'schemas'?: Array<EnumglobalReferentialIntegrityPluginSchemaUrn>;
    /**
     * Name of the Plugin
     * @type {string}
     * @memberof GlobalReferentialIntegrityPluginResponseAllOf
     */
    'id'?: string;
    /**
     * The attribute type(s) for which to maintain referential integrity. The attribute must have a distinguished name or a name and optional UID syntax and must be indexed for equality searches in all subtree views for which referential integrity is to be maintained.
     * @type {Array<string>}
     * @memberof GlobalReferentialIntegrityPluginResponseAllOf
     */
    'attributeType'?: Array<string>;
    /**
     * The subtree view(s) for which to maintain referential integrity.
     * @type {Array<string>}
     * @memberof GlobalReferentialIntegrityPluginResponseAllOf
     */
    'subtreeView'?: Array<string>;
    /**
     * Indicates whether the plug-in is enabled for use.
     * @type {boolean}
     * @memberof GlobalReferentialIntegrityPluginResponseAllOf
     */
    'enabled'?: boolean;
}

