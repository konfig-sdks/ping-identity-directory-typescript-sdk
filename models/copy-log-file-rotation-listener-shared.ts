/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumcopyLogFileRotationListenerSchemaUrn } from './enumcopy-log-file-rotation-listener-schema-urn';

/**
 * 
 * @export
 * @interface CopyLogFileRotationListenerShared
 */
export interface CopyLogFileRotationListenerShared {
    /**
     * A description for this Log File Rotation Listener
     * @type {string}
     * @memberof CopyLogFileRotationListenerShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumcopyLogFileRotationListenerSchemaUrn>}
     * @memberof CopyLogFileRotationListenerShared
     */
    'schemas': Array<EnumcopyLogFileRotationListenerSchemaUrn>;
    /**
     * The path to the directory to which log files should be copied. It must be different from the directory to which the log file is originally written, and administrators should ensure that the filesystem has sufficient space to hold files as they are copied.
     * @type {string}
     * @memberof CopyLogFileRotationListenerShared
     */
    'copyToDirectory': string;
    /**
     * Indicates whether the file should be gzip-compressed as it is copied into the destination directory.
     * @type {boolean}
     * @memberof CopyLogFileRotationListenerShared
     */
    'compressOnCopy'?: boolean;
    /**
     * Indicates whether the Log File Rotation Listener is enabled for use.
     * @type {boolean}
     * @memberof CopyLogFileRotationListenerShared
     */
    'enabled': boolean;
}

