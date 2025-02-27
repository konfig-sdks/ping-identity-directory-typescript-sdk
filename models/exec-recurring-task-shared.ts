/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumexecRecurringTaskSchemaUrn } from './enumexec-recurring-task-schema-urn';
import { EnumrecurringTaskTaskCompletionStateForNonzeroExitCodeProp } from './enumrecurring-task-task-completion-state-for-nonzero-exit-code-prop';

/**
 * 
 * @export
 * @interface ExecRecurringTaskShared
 */
export interface ExecRecurringTaskShared {
    /**
     * A description for this Recurring Task
     * @type {string}
     * @memberof ExecRecurringTaskShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumexecRecurringTaskSchemaUrn>}
     * @memberof ExecRecurringTaskShared
     */
    'schemas': Array<EnumexecRecurringTaskSchemaUrn>;
    /**
     * The absolute path to the command to execute. It must be an absolute path, the corresponding file must exist, and it must be listed in the config/exec-command-whitelist.txt file.
     * @type {string}
     * @memberof ExecRecurringTaskShared
     */
    'commandPath': string;
    /**
     * A string containing the arguments to provide to the command. If the command should be run without arguments, this property should be left undefined. If there should be multiple arguments, then they should be separated with spaces.
     * @type {string}
     * @memberof ExecRecurringTaskShared
     */
    'commandArguments'?: string;
    /**
     * The path and base name for a file to which the command output (both standard output and standard error) should be written. This may be left undefined if the command output should not be recorded into a file.
     * @type {string}
     * @memberof ExecRecurringTaskShared
     */
    'commandOutputFileBaseName'?: string;
    /**
     * The minimum number of previous command output files that should be preserved after a new instance of the command is invoked.
     * @type {number}
     * @memberof ExecRecurringTaskShared
     */
    'retainPreviousOutputFileCount'?: number;
    /**
     * The minimum age of previous command output files that should be preserved after a new instance of the command is invoked.
     * @type {string}
     * @memberof ExecRecurringTaskShared
     */
    'retainPreviousOutputFileAge'?: string;
    /**
     * Indicates whether the command\'s output (both standard output and standard error) should be recorded in the server\'s error log.
     * @type {boolean}
     * @memberof ExecRecurringTaskShared
     */
    'logCommandOutput'?: boolean;
    /**
     * The final task state that a task instance should have if the task executes the specified command and that command completes with a nonzero exit code, which generally means that the command did not complete successfully.
     * @type {EnumrecurringTaskTaskCompletionStateForNonzeroExitCodeProp}
     * @memberof ExecRecurringTaskShared
     */
    'taskCompletionStateForNonzeroExitCode'?: EnumrecurringTaskTaskCompletionStateForNonzeroExitCodeProp;
    /**
     * The absolute path to a working directory where the command should be executed. It must be an absolute path and the corresponding directory must exist.
     * @type {string}
     * @memberof ExecRecurringTaskShared
     */
    'workingDirectory'?: string;
    /**
     * Indicates whether an instance of this Recurring Task should be canceled if the task immediately before it in the recurring task chain fails to complete successfully (including if it is canceled by an administrator before it starts or while it is running).
     * @type {boolean}
     * @memberof ExecRecurringTaskShared
     */
    'cancelOnTaskDependencyFailure'?: boolean;
    /**
     * The email addresses to which a message should be sent whenever an instance of this Recurring Task starts running. If this option is used, then at least one smtp-server must be configured in the global configuration.
     * @type {Array<string>}
     * @memberof ExecRecurringTaskShared
     */
    'emailOnStart'?: Array<string>;
    /**
     * The email addresses to which a message should be sent whenever an instance of this Recurring Task completes successfully. If this option is used, then at least one smtp-server must be configured in the global configuration.
     * @type {Array<string>}
     * @memberof ExecRecurringTaskShared
     */
    'emailOnSuccess'?: Array<string>;
    /**
     * The email addresses to which a message should be sent if an instance of this Recurring Task fails to complete successfully. If this option is used, then at least one smtp-server must be configured in the global configuration.
     * @type {Array<string>}
     * @memberof ExecRecurringTaskShared
     */
    'emailOnFailure'?: Array<string>;
    /**
     * Indicates whether the server should generate an administrative alert whenever an instance of this Recurring Task starts running.
     * @type {boolean}
     * @memberof ExecRecurringTaskShared
     */
    'alertOnStart'?: boolean;
    /**
     * Indicates whether the server should generate an administrative alert whenever an instance of this Recurring Task completes successfully.
     * @type {boolean}
     * @memberof ExecRecurringTaskShared
     */
    'alertOnSuccess'?: boolean;
    /**
     * Indicates whether the server should generate an administrative alert whenever an instance of this Recurring Task fails to complete successfully.
     * @type {boolean}
     * @memberof ExecRecurringTaskShared
     */
    'alertOnFailure'?: boolean;
}

