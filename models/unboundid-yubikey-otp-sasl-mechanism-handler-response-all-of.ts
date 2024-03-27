/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumunboundidYubikeyOtpSaslMechanismHandlerSchemaUrn } from './enumunboundid-yubikey-otp-sasl-mechanism-handler-schema-urn';

/**
 * 
 * @export
 * @interface UnboundidYubikeyOtpSaslMechanismHandlerResponseAllOf
 */
export interface UnboundidYubikeyOtpSaslMechanismHandlerResponseAllOf {
    /**
     * A description for this SASL Mechanism Handler
     * @type {string}
     * @memberof UnboundidYubikeyOtpSaslMechanismHandlerResponseAllOf
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumunboundidYubikeyOtpSaslMechanismHandlerSchemaUrn>}
     * @memberof UnboundidYubikeyOtpSaslMechanismHandlerResponseAllOf
     */
    'schemas'?: Array<EnumunboundidYubikeyOtpSaslMechanismHandlerSchemaUrn>;
    /**
     * Name of the SASL Mechanism Handler
     * @type {string}
     * @memberof UnboundidYubikeyOtpSaslMechanismHandlerResponseAllOf
     */
    'id'?: string;
    /**
     * The client ID to include in requests to the YubiKey validation server. A client ID and API key may be obtained for free from https://upgrade.yubico.com/getapikey/.
     * @type {string}
     * @memberof UnboundidYubikeyOtpSaslMechanismHandlerResponseAllOf
     */
    'yubikeyClientID'?: string;
    /**
     * The API key needed to verify signatures generated by the YubiKey validation server. A client ID and API key may be obtained for free from https://upgrade.yubico.com/getapikey/.
     * @type {string}
     * @memberof UnboundidYubikeyOtpSaslMechanismHandlerResponseAllOf
     */
    'yubikeyAPIKey'?: string;
    /**
     * The passphrase provider to use to obtain the API key needed to verify signatures generated by the YubiKey validation server. A client ID and API key may be obtained for free from https://upgrade.yubico.com/getapikey/.
     * @type {string}
     * @memberof UnboundidYubikeyOtpSaslMechanismHandlerResponseAllOf
     */
    'yubikeyAPIKeyPassphraseProvider'?: string;
    /**
     * The base URL of the validation server to use to verify one-time passwords. You should only need to change the value if you wish to use your own validation server instead of using one of the Yubico servers. The server must use the YubiKey Validation Protocol version 2.0.
     * @type {Array<string>}
     * @memberof UnboundidYubikeyOtpSaslMechanismHandlerResponseAllOf
     */
    'yubikeyValidationServerBaseURL'?: Array<string>;
    /**
     * A reference to an HTTP proxy server that should be used for requests sent to the YubiKey validation service.
     * @type {string}
     * @memberof UnboundidYubikeyOtpSaslMechanismHandlerResponseAllOf
     */
    'httpProxyExternalServer'?: string;
    /**
     * The maximum length of time to wait to obtain an HTTP connection.
     * @type {string}
     * @memberof UnboundidYubikeyOtpSaslMechanismHandlerResponseAllOf
     */
    'httpConnectTimeout'?: string;
    /**
     * The maximum length of time to wait for a response to an HTTP request.
     * @type {string}
     * @memberof UnboundidYubikeyOtpSaslMechanismHandlerResponseAllOf
     */
    'httpResponseTimeout'?: string;
    /**
     * The identity mapper that should be used to identify the user(s) targeted in the authentication and/or authorization identities contained in the bind request. This will only be used for \"u:\"-style identities.
     * @type {string}
     * @memberof UnboundidYubikeyOtpSaslMechanismHandlerResponseAllOf
     */
    'identityMapper'?: string;
    /**
     * Indicates whether a user will be required to provide a static password when authenticating via the UNBOUNDID-YUBIKEY-OTP SASL mechanism.
     * @type {boolean}
     * @memberof UnboundidYubikeyOtpSaslMechanismHandlerResponseAllOf
     */
    'requireStaticPassword'?: boolean;
    /**
     * Specifies which key manager provider should be used to obtain a client certificate to present to the validation server when performing HTTPS communication. This may be left undefined if communication will not be secured with HTTPS, or if there is no need to present a client certificate to the validation service.
     * @type {string}
     * @memberof UnboundidYubikeyOtpSaslMechanismHandlerResponseAllOf
     */
    'keyManagerProvider'?: string;
    /**
     * Specifies which trust manager provider should be used to determine whether to trust the certificate presented by the server when performing HTTPS communication. This may be left undefined if HTTPS communication is not needed, or if the validation service presents a certificate that is trusted by the default JVM configuration (which should be the case for the validation servers that Yubico provides, but may not be the case if an alternate validation server is configured).
     * @type {string}
     * @memberof UnboundidYubikeyOtpSaslMechanismHandlerResponseAllOf
     */
    'trustManagerProvider'?: string;
    /**
     * Indicates whether the SASL mechanism handler is enabled for use.
     * @type {boolean}
     * @memberof UnboundidYubikeyOtpSaslMechanismHandlerResponseAllOf
     */
    'enabled'?: boolean;
}

