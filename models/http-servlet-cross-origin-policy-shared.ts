/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumhttpServletCrossOriginPolicySchemaUrn } from './enumhttp-servlet-cross-origin-policy-schema-urn';

/**
 * 
 * @export
 * @interface HttpServletCrossOriginPolicyShared
 */
export interface HttpServletCrossOriginPolicyShared {
    /**
     * A description for this HTTP Servlet Cross Origin Policy
     * @type {string}
     * @memberof HttpServletCrossOriginPolicyShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumhttpServletCrossOriginPolicySchemaUrn>}
     * @memberof HttpServletCrossOriginPolicyShared
     */
    'schemas'?: Array<EnumhttpServletCrossOriginPolicySchemaUrn>;
    /**
     * A list of HTTP methods allowed for cross-origin access to resources. i.e. one or more of GET, POST, PUT, DELETE, etc.
     * @type {Array<string>}
     * @memberof HttpServletCrossOriginPolicyShared
     */
    'corsAllowedMethods'?: Array<string>;
    /**
     * A list of origins that are allowed to execute cross-origin requests.
     * @type {Array<string>}
     * @memberof HttpServletCrossOriginPolicyShared
     */
    'corsAllowedOrigins'?: Array<string>;
    /**
     * A list of HTTP headers other than the simple response headers that browsers are allowed to access.
     * @type {Array<string>}
     * @memberof HttpServletCrossOriginPolicyShared
     */
    'corsExposedHeaders'?: Array<string>;
    /**
     * A list of HTTP headers that are supported by the resource and can be specified in a cross-origin request.
     * @type {Array<string>}
     * @memberof HttpServletCrossOriginPolicyShared
     */
    'corsAllowedHeaders'?: Array<string>;
    /**
     * The maximum amount of time that a preflight request can be cached by a client.
     * @type {string}
     * @memberof HttpServletCrossOriginPolicyShared
     */
    'corsPreflightMaxAge'?: string;
    /**
     * Indicates whether the servlet extension allows CORS requests with username/password credentials.
     * @type {boolean}
     * @memberof HttpServletCrossOriginPolicyShared
     */
    'corsAllowCredentials'?: boolean;
}

