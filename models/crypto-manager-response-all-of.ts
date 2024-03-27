/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumcryptoManagerSchemaUrn } from './enumcrypto-manager-schema-urn';

/**
 * 
 * @export
 * @interface CryptoManagerResponseAllOf
 */
export interface CryptoManagerResponseAllOf {
    /**
     * 
     * @type {Array<EnumcryptoManagerSchemaUrn>}
     * @memberof CryptoManagerResponseAllOf
     */
    'schemas'?: Array<EnumcryptoManagerSchemaUrn>;
    /**
     * Specifies the preferred message digest algorithm for the Directory Server.
     * @type {string}
     * @memberof CryptoManagerResponseAllOf
     */
    'digestAlgorithm'?: string;
    /**
     * Specifies the preferred MAC algorithm for the Directory Server.
     * @type {string}
     * @memberof CryptoManagerResponseAllOf
     */
    'macAlgorithm'?: string;
    /**
     * Specifies the key length in bits for the preferred MAC algorithm.
     * @type {number}
     * @memberof CryptoManagerResponseAllOf
     */
    'macKeyLength'?: number;
    /**
     * The ID of the encryption settings definition to use for generating digital signatures. If this is not specified, then the server\'s preferred encryption settings definition will be used.
     * @type {string}
     * @memberof CryptoManagerResponseAllOf
     */
    'signingEncryptionSettingsID'?: string;
    /**
     * Specifies the cipher for the Directory Server using the syntax algorithm/mode/padding.
     * @type {string}
     * @memberof CryptoManagerResponseAllOf
     */
    'cipherTransformation'?: string;
    /**
     * Specifies the key length in bits for the preferred cipher.
     * @type {number}
     * @memberof CryptoManagerResponseAllOf
     */
    'cipherKeyLength'?: number;
    /**
     * The preferred key wrapping transformation for the Directory Server. This value must be the same for all server instances in a replication topology.
     * @type {string}
     * @memberof CryptoManagerResponseAllOf
     */
    'keyWrappingTransformation'?: string;
    /**
     * Specifies the names of TLS protocols that are allowed for use in secure communication.
     * @type {Array<string>}
     * @memberof CryptoManagerResponseAllOf
     */
    'sslProtocol'?: Array<string>;
    /**
     * Specifies the names of the TLS cipher suites that are allowed for use in secure communication.
     * @type {Array<string>}
     * @memberof CryptoManagerResponseAllOf
     */
    'sslCipherSuite'?: Array<string>;
    /**
     * Specifies the names of the TLS protocols that will be enabled for outbound connections initiated by the Directory Server.
     * @type {Array<string>}
     * @memberof CryptoManagerResponseAllOf
     */
    'outboundSSLProtocol'?: Array<string>;
    /**
     * Specifies the names of the TLS cipher suites that will be enabled for outbound connections initiated by the Directory Server.
     * @type {Array<string>}
     * @memberof CryptoManagerResponseAllOf
     */
    'outboundSSLCipherSuite'?: Array<string>;
    /**
     * Indicates whether to enable support for TLS cipher suites that use the SHA-1 digest algorithm. The SHA-1 digest algorithm is no longer considered secure and is not recommended for use.
     * @type {boolean}
     * @memberof CryptoManagerResponseAllOf
     */
    'enableSha1CipherSuites'?: boolean;
    /**
     * Indicates whether to enable support for TLS cipher suites that use the RSA key exchange algorithm. Cipher suites that rely on RSA key exchange are not recommended because they do not support forward secrecy, which means that if the private key is compromised, then any communication negotiated using that private key should also be considered compromised.
     * @type {boolean}
     * @memberof CryptoManagerResponseAllOf
     */
    'enableRsaKeyExchangeCipherSuites'?: boolean;
    /**
     * Specifies the nickname (also called the alias) of the certificate that the Crypto Manager should use when performing SSL communication.
     * @type {string}
     * @memberof CryptoManagerResponseAllOf
     */
    'sslCertNickname'?: string;
}

