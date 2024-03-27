/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumidTokenValidatorAllowedSigningAlgorithmProp } from './enumid-token-validator-allowed-signing-algorithm-prop';
import { EnumopenidConnectIdTokenValidatorSchemaUrn } from './enumopenid-connect-id-token-validator-schema-urn';

/**
 * 
 * @export
 * @interface OpenidConnectIdTokenValidatorShared
 */
export interface OpenidConnectIdTokenValidatorShared {
    /**
     * A description for this ID Token Validator
     * @type {string}
     * @memberof OpenidConnectIdTokenValidatorShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumopenidConnectIdTokenValidatorSchemaUrn>}
     * @memberof OpenidConnectIdTokenValidatorShared
     */
    'schemas': Array<EnumopenidConnectIdTokenValidatorSchemaUrn>;
    /**
     * 
     * @type {Array<EnumidTokenValidatorAllowedSigningAlgorithmProp>}
     * @memberof OpenidConnectIdTokenValidatorShared
     */
    'allowedSigningAlgorithm': Array<EnumidTokenValidatorAllowedSigningAlgorithmProp>;
    /**
     * Specifies the locally stored certificates that may be used to validate the signature of an incoming ID token. This property may be specified if a JWKS endpoint should not be used to retrieve public signing keys.
     * @type {Array<string>}
     * @memberof OpenidConnectIdTokenValidatorShared
     */
    'signingCertificate'?: Array<string>;
    /**
     * Specifies the OpenID Connect provider that issues ID tokens handled by this OpenID Connect ID Token Validator. This property is used in conjunction with the jwks-endpoint-path property.
     * @type {string}
     * @memberof OpenidConnectIdTokenValidatorShared
     */
    'OpenIDConnectProvider'?: string;
    /**
     * The relative path to the JWKS endpoint from which to retrieve one or more public signing keys that may be used to validate the signature of an incoming ID token. This path is relative to the base_url property defined for the validator\'s OpenID Connect provider. If jwks-endpoint-path is specified, the OpenID Connect ID Token Validator will not consult locally stored certificates for validating token signatures.
     * @type {string}
     * @memberof OpenidConnectIdTokenValidatorShared
     */
    'jwksEndpointPath'?: string;
    /**
     * Indicates whether this ID Token Validator is enabled for use in the Directory Server.
     * @type {boolean}
     * @memberof OpenidConnectIdTokenValidatorShared
     */
    'enabled': boolean;
    /**
     * Specifies the name of the Identity Mapper that should be used to correlate an ID token subject value to a user entry. The claim name from which to obtain the subject (i.e. the currently logged-in user) may be configured using the subject-claim-name property.
     * @type {string}
     * @memberof OpenidConnectIdTokenValidatorShared
     */
    'identityMapper': string;
    /**
     * The name of the token claim that contains the subject; i.e., the authenticated user.
     * @type {string}
     * @memberof OpenidConnectIdTokenValidatorShared
     */
    'subjectClaimName'?: string;
    /**
     * Specifies the OpenID Connect provider\'s issuer URL.
     * @type {string}
     * @memberof OpenidConnectIdTokenValidatorShared
     */
    'issuerURL': string;
    /**
     * Specifies the amount of clock skew that is tolerated by the ID Token Validator when evaluating whether a token is within its valid time interval. The duration specified by this parameter will be subtracted from the token\'s not-before (nbf) time and added to the token\'s expiration (exp) time, if present, to allow for any time difference between the local server\'s clock and the token issuer\'s clock.
     * @type {string}
     * @memberof OpenidConnectIdTokenValidatorShared
     */
    'clockSkewGracePeriod'?: string;
    /**
     * How often the ID Token Validator should refresh its cache of JWKS token signing keys.
     * @type {string}
     * @memberof OpenidConnectIdTokenValidatorShared
     */
    'jwksCacheDuration'?: string;
    /**
     * When multiple ID Token Validators are defined for a single Directory Server, this property determines the order in which the ID Token Validators are consulted. Values of this property must be unique among all ID Token Validators defined within Directory Server but not necessarily contiguous. ID Token Validators with lower values will be evaluated first to determine if they are able to validate the ID token.
     * @type {number}
     * @memberof OpenidConnectIdTokenValidatorShared
     */
    'evaluationOrderIndex': number;
}

