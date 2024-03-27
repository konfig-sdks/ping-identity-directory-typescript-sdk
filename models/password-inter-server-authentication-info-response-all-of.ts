/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnuminterServerAuthenticationInfoAuthenticationTypeProp } from './enuminter-server-authentication-info-authentication-type-prop';
import { EnuminterServerAuthenticationInfoPurposeProp } from './enuminter-server-authentication-info-purpose-prop';
import { EnumpasswordInterServerAuthenticationInfoSchemaUrn } from './enumpassword-inter-server-authentication-info-schema-urn';

/**
 * 
 * @export
 * @interface PasswordInterServerAuthenticationInfoResponseAllOf
 */
export interface PasswordInterServerAuthenticationInfoResponseAllOf {
    /**
     * 
     * @type {Array<EnumpasswordInterServerAuthenticationInfoSchemaUrn>}
     * @memberof PasswordInterServerAuthenticationInfoResponseAllOf
     */
    'schemas'?: Array<EnumpasswordInterServerAuthenticationInfoSchemaUrn>;
    /**
     * Name of the Inter Server Authentication Info
     * @type {string}
     * @memberof PasswordInterServerAuthenticationInfoResponseAllOf
     */
    'id'?: string;
    /**
     * Identifies the type of password authentication that will be used.
     * @type {EnuminterServerAuthenticationInfoAuthenticationTypeProp}
     * @memberof PasswordInterServerAuthenticationInfoResponseAllOf
     */
    'authenticationType'?: EnuminterServerAuthenticationInfoAuthenticationTypeProp;
    /**
     * A DN of the username that should be used for the bind request.
     * @type {string}
     * @memberof PasswordInterServerAuthenticationInfoResponseAllOf
     */
    'bindDN'?: string;
    /**
     * The username that should be used for the bind request.
     * @type {string}
     * @memberof PasswordInterServerAuthenticationInfoResponseAllOf
     */
    'username'?: string;
    /**
     * The password for the username or bind-dn.
     * @type {string}
     * @memberof PasswordInterServerAuthenticationInfoResponseAllOf
     */
    'password'?: string;
    /**
     * 
     * @type {Array<EnuminterServerAuthenticationInfoPurposeProp>}
     * @memberof PasswordInterServerAuthenticationInfoResponseAllOf
     */
    'purpose'?: Array<EnuminterServerAuthenticationInfoPurposeProp>;
}

