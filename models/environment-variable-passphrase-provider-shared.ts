/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumenvironmentVariablePassphraseProviderSchemaUrn } from './enumenvironment-variable-passphrase-provider-schema-urn';

/**
 * 
 * @export
 * @interface EnvironmentVariablePassphraseProviderShared
 */
export interface EnvironmentVariablePassphraseProviderShared {
    /**
     * A description for this Passphrase Provider
     * @type {string}
     * @memberof EnvironmentVariablePassphraseProviderShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumenvironmentVariablePassphraseProviderSchemaUrn>}
     * @memberof EnvironmentVariablePassphraseProviderShared
     */
    'schemas': Array<EnumenvironmentVariablePassphraseProviderSchemaUrn>;
    /**
     * The name of the environment variable that is expected to hold the passphrase.
     * @type {string}
     * @memberof EnvironmentVariablePassphraseProviderShared
     */
    'environmentVariable': string;
    /**
     * Indicates whether this Passphrase Provider is enabled for use in the server.
     * @type {boolean}
     * @memberof EnvironmentVariablePassphraseProviderShared
     */
    'enabled': boolean;
}

