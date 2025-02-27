/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumvelocityContextProviderObjectScopeProp } from './enumvelocity-context-provider-object-scope-prop';
import { EnumvelocityToolsVelocityContextProviderSchemaUrn } from './enumvelocity-tools-velocity-context-provider-schema-urn';

/**
 * 
 * @export
 * @interface VelocityToolsVelocityContextProviderShared
 */
export interface VelocityToolsVelocityContextProviderShared {
    /**
     * 
     * @type {Array<EnumvelocityToolsVelocityContextProviderSchemaUrn>}
     * @memberof VelocityToolsVelocityContextProviderShared
     */
    'schemas': Array<EnumvelocityToolsVelocityContextProviderSchemaUrn>;
    /**
     * The fully-qualified name of a Velocity Tool class that will be initialized for each request. May optionally include a path to a properties file used to configure this tool separated from the class name by a semi-colon (;). The path may absolute or relative to the server root.
     * @type {Array<string>}
     * @memberof VelocityToolsVelocityContextProviderShared
     */
    'requestTool'?: Array<string>;
    /**
     * The fully-qualified name of a Velocity Tool class that will be initialized for each session. May optionally include a path to a properties file used to configure this tool separated from the class name by a semi-colon (;). The path may absolute or relative to the server root.
     * @type {Array<string>}
     * @memberof VelocityToolsVelocityContextProviderShared
     */
    'sessionTool'?: Array<string>;
    /**
     * The fully-qualified name of a Velocity Tool class that will be initialized once for the life of the server. May optionally include a path to a properties file used to configure this tool separated from the class name by a semi-colon (;). The path may absolute or relative to the server root.
     * @type {Array<string>}
     * @memberof VelocityToolsVelocityContextProviderShared
     */
    'applicationTool'?: Array<string>;
    /**
     * Indicates whether this Velocity Context Provider is enabled. If set to \'false\' this Velocity Context Provider will not contribute context content for any requests.
     * @type {boolean}
     * @memberof VelocityToolsVelocityContextProviderShared
     */
    'enabled'?: boolean;
    /**
     * Scope for context objects contributed by this Velocity Context Provider. Must be either \'request\' or \'session\' or \'application\'.
     * @type {EnumvelocityContextProviderObjectScopeProp}
     * @memberof VelocityToolsVelocityContextProviderShared
     */
    'objectScope'?: EnumvelocityContextProviderObjectScopeProp;
    /**
     * The name of a view for which this Velocity Context Provider will contribute content.
     * @type {Array<string>}
     * @memberof VelocityToolsVelocityContextProviderShared
     */
    'includedView'?: Array<string>;
    /**
     * The name of a view for which this Velocity Context Provider will not contribute content.
     * @type {Array<string>}
     * @memberof VelocityToolsVelocityContextProviderShared
     */
    'excludedView'?: Array<string>;
    /**
     * Specifies HTTP header fields and values added to response headers for template page requests to which this Velocity Context Provider contributes content.
     * @type {Array<string>}
     * @memberof VelocityToolsVelocityContextProviderShared
     */
    'responseHeader'?: Array<string>;
}

