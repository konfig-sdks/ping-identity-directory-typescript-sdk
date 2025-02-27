/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"


/**
 * The final task state that a task instance should have if the task executes the specified command and that command completes with a nonzero exit code, which generally means that the command did not complete successfully.
 * @export
 * @enum {string}
 */
export type EnumrecurringTaskTaskCompletionStateForNonzeroExitCodeProp = 'stopped-by-error' | 'completed-with-errors' | 'completed-successfully'

