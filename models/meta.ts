/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { MetaMeta } from './meta-meta';
import { MetaUrnPingidentitySchemasConfigurationMessages20 } from './meta-urn-pingidentity-schemas-configuration-messages20';

/**
 * 
 * @export
 * @interface Meta
 */
export interface Meta {
    /**
     * 
     * @type {MetaMeta}
     * @memberof Meta
     */
    'meta'?: MetaMeta;
    /**
     * 
     * @type {MetaUrnPingidentitySchemasConfigurationMessages20}
     * @memberof Meta
     */
    'urn:pingidentity:schemas:configuration:messages:2.0'?: MetaUrnPingidentitySchemasConfigurationMessages20;
}

