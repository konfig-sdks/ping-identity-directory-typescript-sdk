/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumexternalServerHttpHostnameVerificationMethodProp } from './enumexternal-server-http-hostname-verification-method-prop';
import { EnumhttpExternalServerSchemaUrn } from './enumhttp-external-server-schema-urn';

/**
 * 
 * @export
 * @interface HttpExternalServerShared
 */
export interface HttpExternalServerShared {
    /**
     * A description for this External Server
     * @type {string}
     * @memberof HttpExternalServerShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumhttpExternalServerSchemaUrn>}
     * @memberof HttpExternalServerShared
     */
    'schemas': Array<EnumhttpExternalServerSchemaUrn>;
    /**
     * The base URL of the external server, optionally including port number, for example \"https://externalService:9031\".
     * @type {string}
     * @memberof HttpExternalServerShared
     */
    'baseURL': string;
    /**
     * The mechanism for checking if the hostname of the HTTP External Server matches the name(s) stored inside the server\'s X.509 certificate. This is only applicable if SSL is being used for connection security.
     * @type {EnumexternalServerHttpHostnameVerificationMethodProp}
     * @memberof HttpExternalServerShared
     */
    'hostnameVerificationMethod'?: EnumexternalServerHttpHostnameVerificationMethodProp;
    /**
     * The key manager provider to use if SSL (HTTPS) is to be used for connection-level security. When specifying a value for this property (except when using the Null key manager provider) you must ensure that the external server trusts this server\'s public certificate by adding this server\'s public certificate to the external server\'s trust store.
     * @type {string}
     * @memberof HttpExternalServerShared
     */
    'keyManagerProvider'?: string;
    /**
     * The trust manager provider to use if SSL (HTTPS) is to be used for connection-level security.
     * @type {string}
     * @memberof HttpExternalServerShared
     */
    'trustManagerProvider'?: string;
    /**
     * The certificate alias within the keystore to use if SSL (HTTPS) is to be used for connection-level security. When specifying a value for this property you must ensure that the external server trusts this server\'s public certificate by adding this server\'s public certificate to the external server\'s trust store.
     * @type {string}
     * @memberof HttpExternalServerShared
     */
    'sslCertNickname'?: string;
    /**
     * Specifies the maximum length of time to wait for a connection to be established before aborting a request to the server.
     * @type {string}
     * @memberof HttpExternalServerShared
     */
    'connectTimeout'?: string;
    /**
     * Specifies the maximum length of time to wait for response data to be read from an established connection before aborting a request to the server.
     * @type {string}
     * @memberof HttpExternalServerShared
     */
    'responseTimeout'?: string;
}

