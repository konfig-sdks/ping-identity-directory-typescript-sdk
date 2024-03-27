/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumldifExportRecurringTaskSchemaUrn } from './enumldif-export-recurring-task-schema-urn';

/**
 * 
 * @export
 * @interface LdifExportRecurringTaskShared
 */
export interface LdifExportRecurringTaskShared {
    /**
     * A description for this Recurring Task
     * @type {string}
     * @memberof LdifExportRecurringTaskShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumldifExportRecurringTaskSchemaUrn>}
     * @memberof LdifExportRecurringTaskShared
     */
    'schemas': Array<EnumldifExportRecurringTaskSchemaUrn>;
    /**
     * The directory in which LDIF export files will be placed. The directory must already exist.
     * @type {string}
     * @memberof LdifExportRecurringTaskShared
     */
    'ldifDirectory'?: string;
    /**
     * The backend ID for a backend to be exported.
     * @type {Array<string>}
     * @memberof LdifExportRecurringTaskShared
     */
    'backendID'?: Array<string>;
    /**
     * The backend ID for a backend to be excluded from the export.
     * @type {Array<string>}
     * @memberof LdifExportRecurringTaskShared
     */
    'excludeBackendID'?: Array<string>;
    /**
     * Indicates whether to compress the LDIF data as it is exported.
     * @type {boolean}
     * @memberof LdifExportRecurringTaskShared
     */
    'compress'?: boolean;
    /**
     * Indicates whether to encrypt the LDIF data as it exported.
     * @type {boolean}
     * @memberof LdifExportRecurringTaskShared
     */
    'encrypt'?: boolean;
    /**
     * The ID of an encryption settings definition to use to obtain the LDIF export encryption key.
     * @type {string}
     * @memberof LdifExportRecurringTaskShared
     */
    'encryptionSettingsDefinitionID'?: string;
    /**
     * Indicates whether to cryptographically sign the exported data, which will make it possible to detect whether the LDIF data has been altered since it was exported.
     * @type {boolean}
     * @memberof LdifExportRecurringTaskShared
     */
    'sign'?: boolean;
    /**
     * The minimum number of previous LDIF exports that should be preserved after a new export completes successfully.
     * @type {number}
     * @memberof LdifExportRecurringTaskShared
     */
    'retainPreviousLDIFExportCount'?: number;
    /**
     * The minimum age of previous LDIF exports that should be preserved after a new export completes successfully.
     * @type {string}
     * @memberof LdifExportRecurringTaskShared
     */
    'retainPreviousLDIFExportAge'?: string;
    /**
     * The maximum rate, in megabytes per second, at which LDIF exports should be written.
     * @type {number}
     * @memberof LdifExportRecurringTaskShared
     */
    'maxMegabytesPerSecond'?: number;
    /**
     * An optional set of post-LDIF-export task processors that should be invoked for the resulting LDIF export files.
     * @type {Array<string>}
     * @memberof LdifExportRecurringTaskShared
     */
    'postLDIFExportTaskProcessor'?: Array<string>;
    /**
     * Indicates whether an instance of this Recurring Task should be canceled if the task immediately before it in the recurring task chain fails to complete successfully (including if it is canceled by an administrator before it starts or while it is running).
     * @type {boolean}
     * @memberof LdifExportRecurringTaskShared
     */
    'cancelOnTaskDependencyFailure'?: boolean;
    /**
     * The email addresses to which a message should be sent whenever an instance of this Recurring Task starts running. If this option is used, then at least one smtp-server must be configured in the global configuration.
     * @type {Array<string>}
     * @memberof LdifExportRecurringTaskShared
     */
    'emailOnStart'?: Array<string>;
    /**
     * The email addresses to which a message should be sent whenever an instance of this Recurring Task completes successfully. If this option is used, then at least one smtp-server must be configured in the global configuration.
     * @type {Array<string>}
     * @memberof LdifExportRecurringTaskShared
     */
    'emailOnSuccess'?: Array<string>;
    /**
     * The email addresses to which a message should be sent if an instance of this Recurring Task fails to complete successfully. If this option is used, then at least one smtp-server must be configured in the global configuration.
     * @type {Array<string>}
     * @memberof LdifExportRecurringTaskShared
     */
    'emailOnFailure'?: Array<string>;
    /**
     * Indicates whether the server should generate an administrative alert whenever an instance of this Recurring Task starts running.
     * @type {boolean}
     * @memberof LdifExportRecurringTaskShared
     */
    'alertOnStart'?: boolean;
    /**
     * Indicates whether the server should generate an administrative alert whenever an instance of this Recurring Task completes successfully.
     * @type {boolean}
     * @memberof LdifExportRecurringTaskShared
     */
    'alertOnSuccess'?: boolean;
    /**
     * Indicates whether the server should generate an administrative alert whenever an instance of this Recurring Task fails to complete successfully.
     * @type {boolean}
     * @memberof LdifExportRecurringTaskShared
     */
    'alertOnFailure'?: boolean;
}

