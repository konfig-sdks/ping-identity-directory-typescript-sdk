/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumenterLockdownModeRecurringTaskSchemaUrn } from './enumenter-lockdown-mode-recurring-task-schema-urn';

/**
 * 
 * @export
 * @interface EnterLockdownModeRecurringTaskShared
 */
export interface EnterLockdownModeRecurringTaskShared {
    /**
     * A description for this Recurring Task
     * @type {string}
     * @memberof EnterLockdownModeRecurringTaskShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumenterLockdownModeRecurringTaskSchemaUrn>}
     * @memberof EnterLockdownModeRecurringTaskShared
     */
    'schemas': Array<EnumenterLockdownModeRecurringTaskSchemaUrn>;
    /**
     * The reason that the server is being placed in lockdown mode.
     * @type {string}
     * @memberof EnterLockdownModeRecurringTaskShared
     */
    'reason'?: string;
    /**
     * Indicates whether an instance of this Recurring Task should be canceled if the task immediately before it in the recurring task chain fails to complete successfully (including if it is canceled by an administrator before it starts or while it is running).
     * @type {boolean}
     * @memberof EnterLockdownModeRecurringTaskShared
     */
    'cancelOnTaskDependencyFailure'?: boolean;
    /**
     * The email addresses to which a message should be sent whenever an instance of this Recurring Task starts running. If this option is used, then at least one smtp-server must be configured in the global configuration.
     * @type {Array<string>}
     * @memberof EnterLockdownModeRecurringTaskShared
     */
    'emailOnStart'?: Array<string>;
    /**
     * The email addresses to which a message should be sent whenever an instance of this Recurring Task completes successfully. If this option is used, then at least one smtp-server must be configured in the global configuration.
     * @type {Array<string>}
     * @memberof EnterLockdownModeRecurringTaskShared
     */
    'emailOnSuccess'?: Array<string>;
    /**
     * The email addresses to which a message should be sent if an instance of this Recurring Task fails to complete successfully. If this option is used, then at least one smtp-server must be configured in the global configuration.
     * @type {Array<string>}
     * @memberof EnterLockdownModeRecurringTaskShared
     */
    'emailOnFailure'?: Array<string>;
    /**
     * Indicates whether the server should generate an administrative alert whenever an instance of this Recurring Task starts running.
     * @type {boolean}
     * @memberof EnterLockdownModeRecurringTaskShared
     */
    'alertOnStart'?: boolean;
    /**
     * Indicates whether the server should generate an administrative alert whenever an instance of this Recurring Task completes successfully.
     * @type {boolean}
     * @memberof EnterLockdownModeRecurringTaskShared
     */
    'alertOnSuccess'?: boolean;
    /**
     * Indicates whether the server should generate an administrative alert whenever an instance of this Recurring Task fails to complete successfully.
     * @type {boolean}
     * @memberof EnterLockdownModeRecurringTaskShared
     */
    'alertOnFailure'?: boolean;
}

