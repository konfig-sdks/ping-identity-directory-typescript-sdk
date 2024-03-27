/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumsynchronizeEncryptionSettingsExtendedOperationHandlerSchemaUrn } from './enumsynchronize-encryption-settings-extended-operation-handler-schema-urn';

/**
 * 
 * @export
 * @interface SynchronizeEncryptionSettingsExtendedOperationHandlerResponseAllOf
 */
export interface SynchronizeEncryptionSettingsExtendedOperationHandlerResponseAllOf {
    /**
     * A description for this Extended Operation Handler
     * @type {string}
     * @memberof SynchronizeEncryptionSettingsExtendedOperationHandlerResponseAllOf
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumsynchronizeEncryptionSettingsExtendedOperationHandlerSchemaUrn>}
     * @memberof SynchronizeEncryptionSettingsExtendedOperationHandlerResponseAllOf
     */
    'schemas'?: Array<EnumsynchronizeEncryptionSettingsExtendedOperationHandlerSchemaUrn>;
    /**
     * Name of the Extended Operation Handler
     * @type {string}
     * @memberof SynchronizeEncryptionSettingsExtendedOperationHandlerResponseAllOf
     */
    'id'?: string;
    /**
     * Indicates whether the Extended Operation Handler is enabled (that is, whether the types of extended operations are allowed in the server).
     * @type {boolean}
     * @memberof SynchronizeEncryptionSettingsExtendedOperationHandlerResponseAllOf
     */
    'enabled'?: boolean;
}

