/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumldapPassThroughAuthenticationHandlerSchemaUrn } from './enumldap-pass-through-authentication-handler-schema-urn';
import { EnumpassThroughAuthenticationHandlerServerAccessModeProp } from './enumpass-through-authentication-handler-server-access-mode-prop';

/**
 * 
 * @export
 * @interface LdapPassThroughAuthenticationHandlerShared
 */
export interface LdapPassThroughAuthenticationHandlerShared {
    /**
     * A description for this Pass Through Authentication Handler
     * @type {string}
     * @memberof LdapPassThroughAuthenticationHandlerShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumldapPassThroughAuthenticationHandlerSchemaUrn>}
     * @memberof LdapPassThroughAuthenticationHandlerShared
     */
    'schemas': Array<EnumldapPassThroughAuthenticationHandlerSchemaUrn>;
    /**
     * Specifies the LDAP external server(s) to which authentication attempts should be forwarded.
     * @type {Array<string>}
     * @memberof LdapPassThroughAuthenticationHandlerShared
     */
    'server': Array<string>;
    /**
     * Specifies the manner in which external servers should be used for pass-through authentication attempts if multiple servers are defined.
     * @type {EnumpassThroughAuthenticationHandlerServerAccessModeProp}
     * @memberof LdapPassThroughAuthenticationHandlerShared
     */
    'serverAccessMode'?: EnumpassThroughAuthenticationHandlerServerAccessModeProp;
    /**
     * Specifies one or more DN mappings that may be used to transform bind DNs before attempting to bind to the external servers.
     * @type {Array<string>}
     * @memberof LdapPassThroughAuthenticationHandlerShared
     */
    'dnMap'?: Array<string>;
    /**
     * A pattern to use to construct the bind DN for the simple bind request to send to the remote server. This may consist of a combination of static text and attribute values and other directives enclosed in curly braces.  For example, the value \"cn={cn},ou=People,dc=example,dc=com\" indicates that the remote bind DN should be constructed from the text \"cn=\" followed by the value of the local entry\'s cn attribute followed by the text \"ou=People,dc=example,dc=com\". If an attribute contains the value to use as the bind DN for pass-through authentication, then the pattern may simply be the name of that attribute in curly braces (e.g., if the seeAlso attribute contains the bind DN for the target user, then a bind DN pattern of \"{seeAlso}\" would be appropriate).  Note that a bind DN pattern can be used to construct a bind DN that is not actually a valid LDAP distinguished name. For example, if authentication is being passed through to a Microsoft Active Directory server, then a bind DN pattern could be used to construct a user principal name (UPN) as an alternative to a distinguished name.
     * @type {string}
     * @memberof LdapPassThroughAuthenticationHandlerShared
     */
    'bindDNPattern'?: string;
    /**
     * The base DN to use when searching for the user entry using a filter constructed from the pattern defined in the search-filter-pattern property. If no base DN is specified, the null DN will be used as the search base DN.
     * @type {string}
     * @memberof LdapPassThroughAuthenticationHandlerShared
     */
    'searchBaseDN'?: string;
    /**
     * A pattern to use to construct a filter to use when searching an external server for the entry of the user as whom to bind. For example, \"(mail={uid:ldapFilterEscape}@example.com)\" would construct a search filter to search for a user whose entry in the local server contains a uid attribute whose value appears before \"@example.com\" in the mail attribute in the external server. Note that the \"ldapFilterEscape\" modifier should almost always be used with attributes specified in the pattern.
     * @type {string}
     * @memberof LdapPassThroughAuthenticationHandlerShared
     */
    'searchFilterPattern'?: string;
    /**
     * Specifies the initial number of connections to establish to each external server against which authentication may be attempted.
     * @type {number}
     * @memberof LdapPassThroughAuthenticationHandlerShared
     */
    'initialConnections'?: number;
    /**
     * Specifies the maximum number of connections to maintain to each external server against which authentication may be attempted. This value must be greater than or equal to the value for the initial-connections property.
     * @type {number}
     * @memberof LdapPassThroughAuthenticationHandlerShared
     */
    'maxConnections'?: number;
    /**
     * Indicates whether to take server locations into account when prioritizing the servers to use for pass-through authentication attempts.
     * @type {boolean}
     * @memberof LdapPassThroughAuthenticationHandlerShared
     */
    'useLocation'?: boolean;
    /**
     * The maximum length of time to wait for a response from an external server in the same location as this Directory Server before considering it unavailable.
     * @type {string}
     * @memberof LdapPassThroughAuthenticationHandlerShared
     */
    'maximumAllowedLocalResponseTime'?: string;
    /**
     * The maximum length of time to wait for a response from an external server in a different location from this Directory Server before considering it unavailable.
     * @type {string}
     * @memberof LdapPassThroughAuthenticationHandlerShared
     */
    'maximumAllowedNonlocalResponseTime'?: string;
    /**
     * Indicates whether to include the password policy request control (as defined in draft-behera-ldap-password-policy-10) in bind requests sent to the external server.
     * @type {boolean}
     * @memberof LdapPassThroughAuthenticationHandlerShared
     */
    'usePasswordPolicyControl'?: boolean;
    /**
     * The base DNs for the local users whose authentication attempts may be passed through to the external authentication service.
     * @type {Array<string>}
     * @memberof LdapPassThroughAuthenticationHandlerShared
     */
    'includedLocalEntryBaseDN'?: Array<string>;
    /**
     * A reference to connection criteria that will be used to indicate which bind requests should be passed through to the external authentication service.
     * @type {string}
     * @memberof LdapPassThroughAuthenticationHandlerShared
     */
    'connectionCriteria'?: string;
    /**
     * A reference to request criteria that will be used to indicate which bind requests should be passed through to the external authentication service.
     * @type {string}
     * @memberof LdapPassThroughAuthenticationHandlerShared
     */
    'requestCriteria'?: string;
}

