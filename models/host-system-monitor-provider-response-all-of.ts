/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumhostSystemMonitorProviderSchemaUrn } from './enumhost-system-monitor-provider-schema-urn';

/**
 * 
 * @export
 * @interface HostSystemMonitorProviderResponseAllOf
 */
export interface HostSystemMonitorProviderResponseAllOf {
    /**
     * A description for this Monitor Provider
     * @type {string}
     * @memberof HostSystemMonitorProviderResponseAllOf
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumhostSystemMonitorProviderSchemaUrn>}
     * @memberof HostSystemMonitorProviderResponseAllOf
     */
    'schemas'?: Array<EnumhostSystemMonitorProviderSchemaUrn>;
    /**
     * Name of the Monitor Provider
     * @type {string}
     * @memberof HostSystemMonitorProviderResponseAllOf
     */
    'id'?: string;
    /**
     * Indicates whether the Host System Monitor Provider is enabled for use.
     * @type {boolean}
     * @memberof HostSystemMonitorProviderResponseAllOf
     */
    'enabled'?: boolean;
    /**
     * Specifies which disk devices to monitor for I/O activity. Should be the device name as displayed by iostat -d.
     * @type {Array<string>}
     * @memberof HostSystemMonitorProviderResponseAllOf
     */
    'diskDevices'?: Array<string>;
    /**
     * Specifies which network interfaces to monitor for I/O activity. Should be the device name as displayed by netstat -i.
     * @type {Array<string>}
     * @memberof HostSystemMonitorProviderResponseAllOf
     */
    'networkDevices'?: Array<string>;
    /**
     * Specifies a relative or absolute path to the directory on the local filesystem containing the log files used by the system utilization monitor. The path must exist, and it must be a writable directory by the server process.
     * @type {string}
     * @memberof HostSystemMonitorProviderResponseAllOf
     */
    'systemUtilizationMonitorLogDirectory'?: string;
}

