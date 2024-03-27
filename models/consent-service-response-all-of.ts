/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumconsentServiceSchemaUrn } from './enumconsent-service-schema-urn';

/**
 * 
 * @export
 * @interface ConsentServiceResponseAllOf
 */
export interface ConsentServiceResponseAllOf {
    /**
     * 
     * @type {Array<EnumconsentServiceSchemaUrn>}
     * @memberof ConsentServiceResponseAllOf
     */
    'schemas'?: Array<EnumconsentServiceSchemaUrn>;
    /**
     * Indicates whether the Consent Service is enabled.
     * @type {boolean}
     * @memberof ConsentServiceResponseAllOf
     */
    'enabled'?: boolean;
    /**
     * The base DN under which consent records are stored.
     * @type {string}
     * @memberof ConsentServiceResponseAllOf
     */
    'baseDN'?: string;
    /**
     * The DN of an internal service account used by the Consent Service to make internal LDAP requests.
     * @type {string}
     * @memberof ConsentServiceResponseAllOf
     */
    'bindDN'?: string;
    /**
     * The maximum number of consent resources that may be returned from a search request.
     * @type {number}
     * @memberof ConsentServiceResponseAllOf
     */
    'searchSizeLimit'?: number;
    /**
     * If specified, the Identity Mapper(s) that may be used to map consent record subject and actor values to DNs. This is typically only needed if privileged API clients will be used.
     * @type {Array<string>}
     * @memberof ConsentServiceResponseAllOf
     */
    'consentRecordIdentityMapper'?: Array<string>;
    /**
     * The set of account DNs that the Consent Service will consider to be privileged.
     * @type {Array<string>}
     * @memberof ConsentServiceResponseAllOf
     */
    'serviceAccountDN'?: Array<string>;
    /**
     * The name of a scope that must be present in an access token accepted by the Consent Service for unprivileged clients.
     * @type {string}
     * @memberof ConsentServiceResponseAllOf
     */
    'unprivilegedConsentScope'?: string;
    /**
     * The name of a scope that must be present in an access token accepted by the Consent Service if the client is to be considered privileged.
     * @type {string}
     * @memberof ConsentServiceResponseAllOf
     */
    'privilegedConsentScope'?: string;
    /**
     * A string or URI that identifies the Consent Service in the context of OAuth2 authorization.
     * @type {string}
     * @memberof ConsentServiceResponseAllOf
     */
    'audience'?: string;
}

