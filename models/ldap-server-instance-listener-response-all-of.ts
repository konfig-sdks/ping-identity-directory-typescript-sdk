/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumldapServerInstanceListenerSchemaUrn } from './enumldap-server-instance-listener-schema-urn';
import { EnumserverInstanceListenerLdapConnectionSecurityProp } from './enumserver-instance-listener-ldap-connection-security-prop';
import { EnumserverInstanceListenerPurposeProp } from './enumserver-instance-listener-purpose-prop';

/**
 * 
 * @export
 * @interface LdapServerInstanceListenerResponseAllOf
 */
export interface LdapServerInstanceListenerResponseAllOf {
    /**
     * 
     * @type {Array<EnumldapServerInstanceListenerSchemaUrn>}
     * @memberof LdapServerInstanceListenerResponseAllOf
     */
    'schemas'?: Array<EnumldapServerInstanceListenerSchemaUrn>;
    /**
     * Name of the Server Instance Listener
     * @type {string}
     * @memberof LdapServerInstanceListenerResponseAllOf
     */
    'id'?: string;
    /**
     * The TCP port number on which the LDAP server is listening.
     * @type {number}
     * @memberof LdapServerInstanceListenerResponseAllOf
     */
    'serverLDAPPort'?: number;
    /**
     * Specifies the mechanism to use for securing connections to the server.
     * @type {EnumserverInstanceListenerLdapConnectionSecurityProp}
     * @memberof LdapServerInstanceListenerResponseAllOf
     */
    'connectionSecurity'?: EnumserverInstanceListenerLdapConnectionSecurityProp;
    /**
     * The public component of the certificate that the listener is expected to present to clients. When establishing a connection to this server, only the certificate(s) listed here will be trusted.
     * @type {string}
     * @memberof LdapServerInstanceListenerResponseAllOf
     */
    'listenerCertificate'?: string;
    /**
     * 
     * @type {Array<EnumserverInstanceListenerPurposeProp>}
     * @memberof LdapServerInstanceListenerResponseAllOf
     */
    'purpose'?: Array<EnumserverInstanceListenerPurposeProp>;
}

