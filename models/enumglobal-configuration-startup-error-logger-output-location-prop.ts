/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"


/**
 * Specifies how the server should handle error log messages (which may include errors, warnings, and notices) generated during startup. All of these messages will be written to all configured error loggers, but they may also be written to other locations (like standard output, standard error, or the server.out log file) so that they are displayed on the console when the server is starting.
 * @export
 * @enum {string}
 */
export type EnumglobalConfigurationStartupErrorLoggerOutputLocationProp = 'standard-output' | 'standard-error' | 'server-out-file' | 'standard-output-and-server-out-file' | 'standard-error-and-server-out-file' | 'disabled'

