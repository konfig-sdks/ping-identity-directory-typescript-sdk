/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumauthorizeServerInstanceSchemaUrn } from './enumauthorize-server-instance-schema-urn';
import { EnumserverInstancePreferredSecurityProp } from './enumserver-instance-preferred-security-prop';
import { EnumserverInstanceServerInstanceTypeProp } from './enumserver-instance-server-instance-type-prop';

/**
 * 
 * @export
 * @interface AuthorizeServerInstanceResponseAllOf
 */
export interface AuthorizeServerInstanceResponseAllOf {
    /**
     * 
     * @type {Array<EnumauthorizeServerInstanceSchemaUrn>}
     * @memberof AuthorizeServerInstanceResponseAllOf
     */
    'schemas'?: Array<EnumauthorizeServerInstanceSchemaUrn>;
    /**
     * Name of the Server Instance
     * @type {string}
     * @memberof AuthorizeServerInstanceResponseAllOf
     */
    'id'?: string;
    /**
     * Specifies the type of server installation.
     * @type {EnumserverInstanceServerInstanceTypeProp}
     * @memberof AuthorizeServerInstanceResponseAllOf
     */
    'serverInstanceType'?: EnumserverInstanceServerInstanceTypeProp;
    /**
     * The name of this Server Instance. The instance name needs to be unique if this server will be part of a topology of servers that are connected to each other. Once set, it may not be changed.
     * @type {string}
     * @memberof AuthorizeServerInstanceResponseAllOf
     */
    'serverInstanceName'?: string;
    /**
     * The name of the cluster to which this Server Instance belongs. Server instances within the same cluster will share the same cluster-wide configuration.
     * @type {string}
     * @memberof AuthorizeServerInstanceResponseAllOf
     */
    'clusterName'?: string;
    /**
     * Specifies the location for the Server Instance.
     * @type {string}
     * @memberof AuthorizeServerInstanceResponseAllOf
     */
    'serverInstanceLocation'?: string;
    /**
     * The name of the host where this Server Instance is installed.
     * @type {string}
     * @memberof AuthorizeServerInstanceResponseAllOf
     */
    'hostname'?: string;
    /**
     * The file system path where this Server Instance is installed.
     * @type {string}
     * @memberof AuthorizeServerInstanceResponseAllOf
     */
    'serverRoot'?: string;
    /**
     * The version of the server.
     * @type {string}
     * @memberof AuthorizeServerInstanceResponseAllOf
     */
    'serverVersion'?: string;
    /**
     * The public component of the certificate used by this instance to protect inter-server communication and to perform server-specific encryption. This will generally be managed by the server and should only be altered by administrators under explicit direction from Ping Identity support personnel.
     * @type {string}
     * @memberof AuthorizeServerInstanceResponseAllOf
     */
    'interServerCertificate'?: string;
    /**
     * The TCP port on which this server is listening for LDAP connections.
     * @type {number}
     * @memberof AuthorizeServerInstanceResponseAllOf
     */
    'ldapPort'?: number;
    /**
     * The TCP port on which this server is listening for LDAP secure connections.
     * @type {number}
     * @memberof AuthorizeServerInstanceResponseAllOf
     */
    'ldapsPort'?: number;
    /**
     * The TCP port on which this server is listening for HTTP connections.
     * @type {number}
     * @memberof AuthorizeServerInstanceResponseAllOf
     */
    'httpPort'?: number;
    /**
     * The TCP port on which this server is listening for HTTPS connections.
     * @type {number}
     * @memberof AuthorizeServerInstanceResponseAllOf
     */
    'httpsPort'?: number;
    /**
     * The replication TCP port.
     * @type {number}
     * @memberof AuthorizeServerInstanceResponseAllOf
     */
    'replicationPort'?: number;
    /**
     * Specifies a unique identifier for the replication server on this server instance.
     * @type {number}
     * @memberof AuthorizeServerInstanceResponseAllOf
     */
    'replicationServerID'?: number;
    /**
     * Specifies a unique identifier for the Directory Server within the replication domain.
     * @type {Array<number>}
     * @memberof AuthorizeServerInstanceResponseAllOf
     */
    'replicationDomainServerID'?: Array<number>;
    /**
     * The TCP port on which this server is listening for JMX connections.
     * @type {number}
     * @memberof AuthorizeServerInstanceResponseAllOf
     */
    'jmxPort'?: number;
    /**
     * The TCP port on which this server is listening for JMX secure connections.
     * @type {number}
     * @memberof AuthorizeServerInstanceResponseAllOf
     */
    'jmxsPort'?: number;
    /**
     * Specifies the preferred mechanism to use for securing connections to the server.
     * @type {EnumserverInstancePreferredSecurityProp}
     * @memberof AuthorizeServerInstanceResponseAllOf
     */
    'preferredSecurity'?: EnumserverInstancePreferredSecurityProp;
    /**
     * Indicates whether StartTLS is enabled on this server.
     * @type {boolean}
     * @memberof AuthorizeServerInstanceResponseAllOf
     */
    'startTLSEnabled'?: boolean;
    /**
     * The set of base DNs under the root DSE.
     * @type {Array<string>}
     * @memberof AuthorizeServerInstanceResponseAllOf
     */
    'baseDN'?: Array<string>;
    /**
     * The set of groups of which this server is a member.
     * @type {Array<string>}
     * @memberof AuthorizeServerInstanceResponseAllOf
     */
    'memberOfServerGroup'?: Array<string>;
}

