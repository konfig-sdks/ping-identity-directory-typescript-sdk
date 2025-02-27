/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumoauthBearerSaslMechanismHandlerSchemaUrn } from './enumoauth-bearer-sasl-mechanism-handler-schema-urn';
import { EnumsaslMechanismHandlerValidateAccessTokenWhenIDTokenIsAlsoProvidedProp } from './enumsasl-mechanism-handler-validate-access-token-when-idtoken-is-also-provided-prop';

/**
 * 
 * @export
 * @interface OauthBearerSaslMechanismHandlerShared
 */
export interface OauthBearerSaslMechanismHandlerShared {
    /**
     * A description for this SASL Mechanism Handler
     * @type {string}
     * @memberof OauthBearerSaslMechanismHandlerShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumoauthBearerSaslMechanismHandlerSchemaUrn>}
     * @memberof OauthBearerSaslMechanismHandlerShared
     */
    'schemas': Array<EnumoauthBearerSaslMechanismHandlerSchemaUrn>;
    /**
     * An access token validator that will ensure that each presented OAuth access token is authentic and trustworthy. It must be configured with an identity mapper that will be used to map the access token to a local entry.
     * @type {Array<string>}
     * @memberof OauthBearerSaslMechanismHandlerShared
     */
    'accessTokenValidator'?: Array<string>;
    /**
     * An ID token validator that will ensure that each presented OpenID Connect ID token is authentic and trustworthy, and that will map the token to a local entry.
     * @type {Array<string>}
     * @memberof OauthBearerSaslMechanismHandlerShared
     */
    'idTokenValidator'?: Array<string>;
    /**
     * Indicates whether bind requests will be required to have both an OAuth access token (in the \"auth\" element of the bind request) and an OpenID Connect ID token (in the \"pingidentityidtoken\" element of the bind request).
     * @type {boolean}
     * @memberof OauthBearerSaslMechanismHandlerShared
     */
    'requireBothAccessTokenAndIDToken'?: boolean;
    /**
     * Indicates whether to validate the OAuth access token in addition to the OpenID Connect ID token in OAUTHBEARER bind requests that contain both types of tokens.
     * @type {EnumsaslMechanismHandlerValidateAccessTokenWhenIDTokenIsAlsoProvidedProp}
     * @memberof OauthBearerSaslMechanismHandlerShared
     */
    'validateAccessTokenWhenIDTokenIsAlsoProvided'?: EnumsaslMechanismHandlerValidateAccessTokenWhenIDTokenIsAlsoProvidedProp;
    /**
     * The identity mapper that will be used to map an alternate authorization identity (provided in the GS2 header of the encoded OAUTHBEARER bind request credentials) to the corresponding local entry.
     * @type {string}
     * @memberof OauthBearerSaslMechanismHandlerShared
     */
    'alternateAuthorizationIdentityMapper'?: string;
    /**
     * The set of OAuth scopes that will all be required for any access tokens that will be allowed for authentication.
     * @type {Array<string>}
     * @memberof OauthBearerSaslMechanismHandlerShared
     */
    'allRequiredScope'?: Array<string>;
    /**
     * The set of OAuth scopes that a token may have to be allowed for authentication.
     * @type {Array<string>}
     * @memberof OauthBearerSaslMechanismHandlerShared
     */
    'anyRequiredScope'?: Array<string>;
    /**
     * The fully-qualified name that clients are expected to use when communicating with the server.
     * @type {string}
     * @memberof OauthBearerSaslMechanismHandlerShared
     */
    'serverFqdn'?: string;
    /**
     * Indicates whether the SASL mechanism handler is enabled for use.
     * @type {boolean}
     * @memberof OauthBearerSaslMechanismHandlerShared
     */
    'enabled': boolean;
}

