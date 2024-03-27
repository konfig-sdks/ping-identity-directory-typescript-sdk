/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumrootDseBackendSchemaUrn } from './enumroot-dse-backend-schema-urn';

/**
 * 
 * @export
 * @interface RootDseBackendResponseAllOf
 */
export interface RootDseBackendResponseAllOf {
    /**
     * 
     * @type {Array<EnumrootDseBackendSchemaUrn>}
     * @memberof RootDseBackendResponseAllOf
     */
    'schemas'?: Array<EnumrootDseBackendSchemaUrn>;
    /**
     * Specifies the set of base DNs used for singleLevel, wholeSubtree, and subordinateSubtree searches based at the root DSE.
     * @type {Array<string>}
     * @memberof RootDseBackendResponseAllOf
     */
    'subordinateBaseDN'?: Array<string>;
    /**
     * Specifies an additional OID that should appear in the list of supportedControl values in the server\'s root DSE.
     * @type {Array<string>}
     * @memberof RootDseBackendResponseAllOf
     */
    'additionalSupportedControlOID'?: Array<string>;
    /**
     * Indicates whether all attributes in the root DSE are to be treated like user attributes (and therefore returned to clients by default) regardless of the Directory Server schema configuration.
     * @type {boolean}
     * @memberof RootDseBackendResponseAllOf
     */
    'showAllAttributes'?: boolean;
    /**
     * Indicates whether the server\'s root DSE should reflect current or legacy values for the vendorName and vendorVersion attributes.
     * @type {boolean}
     * @memberof RootDseBackendResponseAllOf
     */
    'useLegacyVendorVersion'?: boolean;
}

