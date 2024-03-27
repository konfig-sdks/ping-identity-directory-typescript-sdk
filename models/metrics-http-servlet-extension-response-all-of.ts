/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnummetricsHttpServletExtensionSchemaUrn } from './enummetrics-http-servlet-extension-schema-urn';

/**
 * 
 * @export
 * @interface MetricsHttpServletExtensionResponseAllOf
 */
export interface MetricsHttpServletExtensionResponseAllOf {
    /**
     * A description for this HTTP Servlet Extension
     * @type {string}
     * @memberof MetricsHttpServletExtensionResponseAllOf
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnummetricsHttpServletExtensionSchemaUrn>}
     * @memberof MetricsHttpServletExtensionResponseAllOf
     */
    'schemas'?: Array<EnummetricsHttpServletExtensionSchemaUrn>;
    /**
     * Name of the HTTP Servlet Extension
     * @type {string}
     * @memberof MetricsHttpServletExtensionResponseAllOf
     */
    'id'?: string;
    /**
     * Require authentication when accessing the REST API.
     * @type {boolean}
     * @memberof MetricsHttpServletExtensionResponseAllOf
     */
    'requireAPIAuthentication'?: boolean;
    /**
     * Specifies the name of the identity mapper that is to be used for associating user entries with basic authentication user names.
     * @type {string}
     * @memberof MetricsHttpServletExtensionResponseAllOf
     */
    'identityMapper'?: string;
    /**
     * Specifies that API error messages for invalid queries, unknown resources, service unavailable, and internal server errors are generic in nature.
     * @type {boolean}
     * @memberof MetricsHttpServletExtensionResponseAllOf
     */
    'omitErrorMessageDetails'?: boolean;
    /**
     * Length of time before a REST API authentication session expires.
     * @type {string}
     * @memberof MetricsHttpServletExtensionResponseAllOf
     */
    'apiAuthenticationTimeout'?: string;
    /**
     * The cross-origin request policy to use for the HTTP Servlet Extension.
     * @type {string}
     * @memberof MetricsHttpServletExtensionResponseAllOf
     */
    'crossOriginPolicy'?: string;
    /**
     * Specifies HTTP header fields and values added to response headers for all requests.
     * @type {Array<string>}
     * @memberof MetricsHttpServletExtensionResponseAllOf
     */
    'responseHeader'?: Array<string>;
    /**
     * Specifies the name of the HTTP response header that will contain a correlation ID value. Example values are \"Correlation-Id\", \"X-Amzn-Trace-Id\", and \"X-Request-Id\".
     * @type {string}
     * @memberof MetricsHttpServletExtensionResponseAllOf
     */
    'correlationIDResponseHeader'?: string;
}

