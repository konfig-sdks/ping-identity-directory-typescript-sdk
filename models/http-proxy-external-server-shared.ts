/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumhttpProxyExternalServerSchemaUrn } from './enumhttp-proxy-external-server-schema-urn';

/**
 * 
 * @export
 * @interface HttpProxyExternalServerShared
 */
export interface HttpProxyExternalServerShared {
    /**
     * A description for this External Server
     * @type {string}
     * @memberof HttpProxyExternalServerShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumhttpProxyExternalServerSchemaUrn>}
     * @memberof HttpProxyExternalServerShared
     */
    'schemas': Array<EnumhttpProxyExternalServerSchemaUrn>;
    /**
     * The host name or IP address of the HTTP Proxy External Server.
     * @type {string}
     * @memberof HttpProxyExternalServerShared
     */
    'serverHostName': string;
    /**
     * The port on which the HTTP Proxy External Server is listening for connections.
     * @type {number}
     * @memberof HttpProxyExternalServerShared
     */
    'serverPort': number;
    /**
     * The username to use to authenticate to the HTTP Proxy External Server.
     * @type {string}
     * @memberof HttpProxyExternalServerShared
     */
    'basicAuthenticationUsername'?: string;
    /**
     * A passphrase provider that provides access to the password to use to authenticate to the HTTP Proxy External Server.
     * @type {string}
     * @memberof HttpProxyExternalServerShared
     */
    'basicAuthenticationPassphraseProvider'?: string;
}

