/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumconjurPassphraseProviderSchemaUrn } from './enumconjur-passphrase-provider-schema-urn';

/**
 * 
 * @export
 * @interface ConjurPassphraseProviderShared
 */
export interface ConjurPassphraseProviderShared {
    /**
     * A description for this Passphrase Provider
     * @type {string}
     * @memberof ConjurPassphraseProviderShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumconjurPassphraseProviderSchemaUrn>}
     * @memberof ConjurPassphraseProviderShared
     */
    'schemas': Array<EnumconjurPassphraseProviderSchemaUrn>;
    /**
     * An external server definition with information needed to connect and authenticate to the Conjur instance containing the passphrase.
     * @type {string}
     * @memberof ConjurPassphraseProviderShared
     */
    'conjurExternalServer': string;
    /**
     * The portion of the path that follows the account name in the URI needed to obtain the desired secret. Any special characters in the path must be URL-encoded.
     * @type {string}
     * @memberof ConjurPassphraseProviderShared
     */
    'conjurSecretRelativePath': string;
    /**
     * The maximum length of time that the passphrase provider may cache the passphrase that has been read from Conjur. A value of zero seconds indicates that the provider should always attempt to read the passphrase from Conjur.
     * @type {string}
     * @memberof ConjurPassphraseProviderShared
     */
    'maxCacheDuration'?: string;
    /**
     * Indicates whether this Passphrase Provider is enabled for use in the server.
     * @type {boolean}
     * @memberof ConjurPassphraseProviderShared
     */
    'enabled': boolean;
}

