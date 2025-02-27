/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnummonitoringEndpointConnectionTypeProp } from './enummonitoring-endpoint-connection-type-prop';
import { EnumstatsdMonitoringEndpointSchemaUrn } from './enumstatsd-monitoring-endpoint-schema-urn';

/**
 * 
 * @export
 * @interface StatsdMonitoringEndpointShared
 */
export interface StatsdMonitoringEndpointShared {
    /**
     * 
     * @type {Array<EnumstatsdMonitoringEndpointSchemaUrn>}
     * @memberof StatsdMonitoringEndpointShared
     */
    'schemas': Array<EnumstatsdMonitoringEndpointSchemaUrn>;
    /**
     * The name of the host where this StatsD Monitoring Endpoint should send metric data.
     * @type {string}
     * @memberof StatsdMonitoringEndpointShared
     */
    'hostname': string;
    /**
     * Specifies the port number of the endpoint where metric data should be sent.
     * @type {number}
     * @memberof StatsdMonitoringEndpointShared
     */
    'serverPort'?: number;
    /**
     * Specifies the protocol and security that this StatsD Monitoring Endpoint should use to connect to the configured endpoint.
     * @type {EnummonitoringEndpointConnectionTypeProp}
     * @memberof StatsdMonitoringEndpointShared
     */
    'connectionType'?: EnummonitoringEndpointConnectionTypeProp;
    /**
     * The trust manager provider to use if SSL over TCP is to be used for connection-level security.
     * @type {string}
     * @memberof StatsdMonitoringEndpointShared
     */
    'trustManagerProvider'?: string;
    /**
     * Specifies any optional additional tags to include in StatsD messages. Any additional tags will be appended to the end of each StatsD message, separated by commas. Tags should be written in a [key]:[value] format (\"host:server1\", for example).
     * @type {Array<string>}
     * @memberof StatsdMonitoringEndpointShared
     */
    'additionalTags'?: Array<string>;
    /**
     * Indicates whether this Monitoring Endpoint is enabled for use in the Directory Server.
     * @type {boolean}
     * @memberof StatsdMonitoringEndpointShared
     */
    'enabled': boolean;
}

