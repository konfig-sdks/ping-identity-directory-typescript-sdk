/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumbackendWritabilityModeProp } from './enumbackend-writability-mode-prop';
import { EnumconfigFileHandlerBackendSchemaUrn } from './enumconfig-file-handler-backend-schema-urn';

/**
 * 
 * @export
 * @interface ConfigFileHandlerBackendResponseAllOf
 */
export interface ConfigFileHandlerBackendResponseAllOf {
    /**
     * A description for this Backend
     * @type {string}
     * @memberof ConfigFileHandlerBackendResponseAllOf
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumconfigFileHandlerBackendSchemaUrn>}
     * @memberof ConfigFileHandlerBackendResponseAllOf
     */
    'schemas'?: Array<EnumconfigFileHandlerBackendSchemaUrn>;
    /**
     * Name of the Backend
     * @type {string}
     * @memberof ConfigFileHandlerBackendResponseAllOf
     */
    'id'?: string;
    /**
     * Specifies a name to identify the associated backend.
     * @type {string}
     * @memberof ConfigFileHandlerBackendResponseAllOf
     */
    'backendID'?: string;
    /**
     * Specifies the base DN(s) for the data that the backend handles.
     * @type {Array<string>}
     * @memberof ConfigFileHandlerBackendResponseAllOf
     */
    'baseDN'?: Array<string>;
    /**
     * Specifies the behavior that the backend should use when processing write operations.
     * @type {EnumbackendWritabilityModeProp}
     * @memberof ConfigFileHandlerBackendResponseAllOf
     */
    'writabilityMode'?: EnumbackendWritabilityModeProp;
    /**
     * The name or OID of an attribute type that is considered insignificant for the purpose of maintaining the configuration archive.
     * @type {Array<string>}
     * @memberof ConfigFileHandlerBackendResponseAllOf
     */
    'insignificantConfigArchiveAttribute'?: Array<string>;
    /**
     * The base DN that is considered insignificant for the purpose of maintaining the configuration archive.
     * @type {Array<string>}
     * @memberof ConfigFileHandlerBackendResponseAllOf
     */
    'insignificantConfigArchiveBaseDN'?: Array<string>;
    /**
     * Indicates whether the server should maintain the config archive with new changes to the config backend.
     * @type {boolean}
     * @memberof ConfigFileHandlerBackendResponseAllOf
     */
    'maintainConfigArchive'?: boolean;
    /**
     * Indicates the maximum number of previous config files to keep as part of maintaining the config archive.
     * @type {number}
     * @memberof ConfigFileHandlerBackendResponseAllOf
     */
    'maxConfigArchiveCount'?: number;
    /**
     * Tells the server component that is responsible for mirroring configuration data across a topology of servers the maximum amount of time to wait before polling the peer servers in the topology to determine if there are any changes in the topology. Mirrored data includes meta-data about the servers in the topology as well as cluster-wide configuration data.
     * @type {string}
     * @memberof ConfigFileHandlerBackendResponseAllOf
     */
    'mirroredSubtreePeerPollingInterval'?: string;
    /**
     * Tells the server component that is responsible for mirroring configuration data across a topology of servers the maximum amount of time to wait for an update operation (add, delete, modify and modify-dn) on an entry to be applied on all servers in the topology. Mirrored data includes meta-data about the servers in the topology as well as cluster-wide configuration data.
     * @type {string}
     * @memberof ConfigFileHandlerBackendResponseAllOf
     */
    'mirroredSubtreeEntryUpdateTimeout'?: string;
    /**
     * Tells the server component that is responsible for mirroring configuration data across a topology of servers the maximum amount of time to wait for a search operation to complete. Mirrored data includes meta-data about the servers in the topology as well as cluster-wide configuration data. Search requests that take longer than this timeout will be canceled and considered failures.
     * @type {string}
     * @memberof ConfigFileHandlerBackendResponseAllOf
     */
    'mirroredSubtreeSearchTimeout'?: string;
    /**
     * Indicates whether the backend is enabled in the server.
     * @type {boolean}
     * @memberof ConfigFileHandlerBackendResponseAllOf
     */
    'enabled'?: boolean;
    /**
     * Determines whether the Directory Server enters a DEGRADED state (and sends a corresponding alert) when this Backend is disabled.
     * @type {boolean}
     * @memberof ConfigFileHandlerBackendResponseAllOf
     */
    'setDegradedAlertWhenDisabled'?: boolean;
    /**
     * Determines whether any LDAP operation that would use this Backend is to return UNAVAILABLE when this Backend is disabled.
     * @type {boolean}
     * @memberof ConfigFileHandlerBackendResponseAllOf
     */
    'returnUnavailableWhenDisabled'?: boolean;
    /**
     * Specifies the permissions that should be applied to files and directories created by a backup of the backend.
     * @type {string}
     * @memberof ConfigFileHandlerBackendResponseAllOf
     */
    'backupFilePermissions'?: string;
    /**
     * Specifies a notification manager for changes resulting from operations processed through this Backend
     * @type {string}
     * @memberof ConfigFileHandlerBackendResponseAllOf
     */
    'notificationManager'?: string;
}

