/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumpluginPluginTypeProp } from './enumplugin-plugin-type-prop';
import { EnumreferralOnUpdatePluginSchemaUrn } from './enumreferral-on-update-plugin-schema-urn';

/**
 * 
 * @export
 * @interface ReferralOnUpdatePluginShared
 */
export interface ReferralOnUpdatePluginShared {
    /**
     * A description for this Plugin
     * @type {string}
     * @memberof ReferralOnUpdatePluginShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumreferralOnUpdatePluginSchemaUrn>}
     * @memberof ReferralOnUpdatePluginShared
     */
    'schemas': Array<EnumreferralOnUpdatePluginSchemaUrn>;
    /**
     * 
     * @type {Array<EnumpluginPluginTypeProp>}
     * @memberof ReferralOnUpdatePluginShared
     */
    'pluginType'?: Array<EnumpluginPluginTypeProp>;
    /**
     * Specifies the base URL to use for the referrals generated by this plugin. It should include only the scheme, address, and port to use to communicate with the target server (e.g., \"ldap://server.example.com:389/\").
     * @type {Array<string>}
     * @memberof ReferralOnUpdatePluginShared
     */
    'referralBaseURL': Array<string>;
    /**
     * Specifies a base DN for requests for which to send referrals in response to update operations.
     * @type {Array<string>}
     * @memberof ReferralOnUpdatePluginShared
     */
    'baseDN'?: Array<string>;
    /**
     * Indicates whether the plug-in should be invoked for internal operations.
     * @type {boolean}
     * @memberof ReferralOnUpdatePluginShared
     */
    'invokeForInternalOperations'?: boolean;
    /**
     * Indicates whether the plug-in is enabled for use.
     * @type {boolean}
     * @memberof ReferralOnUpdatePluginShared
     */
    'enabled': boolean;
}

