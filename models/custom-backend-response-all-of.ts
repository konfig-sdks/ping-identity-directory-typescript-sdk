/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumbackendWritabilityModeProp } from './enumbackend-writability-mode-prop';
import { EnumcustomBackendSchemaUrn } from './enumcustom-backend-schema-urn';

/**
 * 
 * @export
 * @interface CustomBackendResponseAllOf
 */
export interface CustomBackendResponseAllOf {
    /**
     * A description for this Backend
     * @type {string}
     * @memberof CustomBackendResponseAllOf
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumcustomBackendSchemaUrn>}
     * @memberof CustomBackendResponseAllOf
     */
    'schemas'?: Array<EnumcustomBackendSchemaUrn>;
    /**
     * Name of the Backend
     * @type {string}
     * @memberof CustomBackendResponseAllOf
     */
    'id'?: string;
    /**
     * Specifies a name to identify the associated backend.
     * @type {string}
     * @memberof CustomBackendResponseAllOf
     */
    'backendID'?: string;
    /**
     * Indicates whether the backend is enabled in the server.
     * @type {boolean}
     * @memberof CustomBackendResponseAllOf
     */
    'enabled'?: boolean;
    /**
     * Specifies the base DN(s) for the data that the backend handles.
     * @type {Array<string>}
     * @memberof CustomBackendResponseAllOf
     */
    'baseDN'?: Array<string>;
    /**
     * Specifies the behavior that the backend should use when processing write operations.
     * @type {EnumbackendWritabilityModeProp}
     * @memberof CustomBackendResponseAllOf
     */
    'writabilityMode'?: EnumbackendWritabilityModeProp;
    /**
     * Determines whether the Directory Server enters a DEGRADED state (and sends a corresponding alert) when this Backend is disabled.
     * @type {boolean}
     * @memberof CustomBackendResponseAllOf
     */
    'setDegradedAlertWhenDisabled'?: boolean;
    /**
     * Determines whether any LDAP operation that would use this Backend is to return UNAVAILABLE when this Backend is disabled.
     * @type {boolean}
     * @memberof CustomBackendResponseAllOf
     */
    'returnUnavailableWhenDisabled'?: boolean;
    /**
     * Specifies the permissions that should be applied to files and directories created by a backup of the backend.
     * @type {string}
     * @memberof CustomBackendResponseAllOf
     */
    'backupFilePermissions'?: string;
    /**
     * Specifies a notification manager for changes resulting from operations processed through this Backend
     * @type {string}
     * @memberof CustomBackendResponseAllOf
     */
    'notificationManager'?: string;
}

