/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumexternalServerDefunctConnectionResultCodeProp } from './enumexternal-server-defunct-connection-result-code-prop';
import { EnumexternalServerNokiaDsAuthenticationMethodProp } from './enumexternal-server-nokia-ds-authentication-method-prop';
import { EnumexternalServerNokiaDsConnectionSecurityProp } from './enumexternal-server-nokia-ds-connection-security-prop';
import { EnumexternalServerVerifyCredentialsMethodProp } from './enumexternal-server-verify-credentials-method-prop';
import { EnumnokiaDsExternalServerSchemaUrn } from './enumnokia-ds-external-server-schema-urn';

/**
 * 
 * @export
 * @interface NokiaDsExternalServerShared
 */
export interface NokiaDsExternalServerShared {
    /**
     * A description for this External Server
     * @type {string}
     * @memberof NokiaDsExternalServerShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumnokiaDsExternalServerSchemaUrn>}
     * @memberof NokiaDsExternalServerShared
     */
    'schemas': Array<EnumnokiaDsExternalServerSchemaUrn>;
    /**
     * The mechanism to use to verify user credentials while ensuring that the ability to process other operations is not impacted by an alternate authorization identity.
     * @type {EnumexternalServerVerifyCredentialsMethodProp}
     * @memberof NokiaDsExternalServerShared
     */
    'verifyCredentialsMethod'?: EnumexternalServerVerifyCredentialsMethodProp;
    /**
     * Indicates whether to include the administrative operation request control in requests sent to this server which are intended for administrative operations (e.g., health checking) rather than requests directly from clients.
     * @type {boolean}
     * @memberof NokiaDsExternalServerShared
     */
    'useAdministrativeOperationControl'?: boolean;
    /**
     * The host name or IP address of the target LDAP server.
     * @type {string}
     * @memberof NokiaDsExternalServerShared
     */
    'serverHostName': string;
    /**
     * The port number on which the server listens for requests.
     * @type {number}
     * @memberof NokiaDsExternalServerShared
     */
    'serverPort'?: number;
    /**
     * Specifies the location for the LDAP External Server.
     * @type {string}
     * @memberof NokiaDsExternalServerShared
     */
    'location'?: string;
    /**
     * The DN to use to bind to the target LDAP server if simple authentication is required.
     * @type {string}
     * @memberof NokiaDsExternalServerShared
     */
    'bindDN'?: string;
    /**
     * The login password for the specified user.
     * @type {string}
     * @memberof NokiaDsExternalServerShared
     */
    'password'?: string;
    /**
     * The passphrase provider to use to obtain the login password for the specified user.
     * @type {string}
     * @memberof NokiaDsExternalServerShared
     */
    'passphraseProvider'?: string;
    /**
     * The mechanism to use to secure communication with the directory server.
     * @type {EnumexternalServerNokiaDsConnectionSecurityProp}
     * @memberof NokiaDsExternalServerShared
     */
    'connectionSecurity'?: EnumexternalServerNokiaDsConnectionSecurityProp;
    /**
     * The mechanism to use to authenticate to the target server.
     * @type {EnumexternalServerNokiaDsAuthenticationMethodProp}
     * @memberof NokiaDsExternalServerShared
     */
    'authenticationMethod'?: EnumexternalServerNokiaDsAuthenticationMethodProp;
    /**
     * Specifies the maximum length of time to wait for a connection to be established for the purpose of performing a health check. If the connection cannot be established within this length of time, the server will be classified as unavailable.
     * @type {string}
     * @memberof NokiaDsExternalServerShared
     */
    'healthCheckConnectTimeout'?: string;
    /**
     * Specifies the maximum length of time that connections to this server should be allowed to remain established before being closed and replaced with newly-established connections.
     * @type {string}
     * @memberof NokiaDsExternalServerShared
     */
    'maxConnectionAge'?: string;
    /**
     * Specifies the minimum length of time that should pass between connection closures as a result of the connections being established for longer than the maximum connection age. This may help avoid cases in which a large number of connections are closed and re-established in a short period of time because of the maximum connection age.
     * @type {string}
     * @memberof NokiaDsExternalServerShared
     */
    'minExpiredConnectionDisconnectInterval'?: string;
    /**
     * Specifies the maximum length of time to wait for a connection to be established before giving up and considering the server unavailable.
     * @type {string}
     * @memberof NokiaDsExternalServerShared
     */
    'connectTimeout'?: string;
    /**
     * Specifies the maximum response size that should be supported for messages received from the LDAP external server.
     * @type {string}
     * @memberof NokiaDsExternalServerShared
     */
    'maxResponseSize'?: string;
    /**
     * The key manager provider to use if SSL or StartTLS is to be used for connection-level security. When specifying a value for this property (except when using the Null key manager provider) you must ensure that the external server trusts this server\'s public certificate by adding this server\'s public certificate to the external server\'s trust store.
     * @type {string}
     * @memberof NokiaDsExternalServerShared
     */
    'keyManagerProvider'?: string;
    /**
     * The trust manager provider to use if SSL or StartTLS is to be used for connection-level security.
     * @type {string}
     * @memberof NokiaDsExternalServerShared
     */
    'trustManagerProvider'?: string;
    /**
     * The number of connections to initially establish to the LDAP external server. A value of zero indicates that the number of connections should be dynamically based on the number of available worker threads. This will be ignored when using a thread-local connection pool.
     * @type {number}
     * @memberof NokiaDsExternalServerShared
     */
    'initialConnections'?: number;
    /**
     * The maximum number of concurrent connections to maintain for the LDAP external server. A value of zero indicates that the number of connections should be dynamically based on the number of available worker threads. This will be ignored when using a thread-local connection pool.
     * @type {number}
     * @memberof NokiaDsExternalServerShared
     */
    'maxConnections'?: number;
    /**
     * 
     * @type {Array<EnumexternalServerDefunctConnectionResultCodeProp>}
     * @memberof NokiaDsExternalServerShared
     */
    'defunctConnectionResultCode'?: Array<EnumexternalServerDefunctConnectionResultCodeProp>;
    /**
     * Indicates whether to send an abandon request for an operation for which a response timeout is encountered. A request which has timed out on one server may be retried on another server regardless of whether an abandon request is sent, but if the initial attempt is not abandoned then a long-running operation may unnecessarily continue to consume processing resources on the initial server.
     * @type {boolean}
     * @memberof NokiaDsExternalServerShared
     */
    'abandonOnTimeout'?: boolean;
}

