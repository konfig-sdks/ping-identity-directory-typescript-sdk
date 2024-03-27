/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"


/**
 * Specifies a set of TLS protocols that will be permitted for use in the server even though there may be known vulnerabilities that could cause their use to be unsafe in some conditions. Enabling support for insecure TLS protocols is discouraged, and is generally recommended only as a short-term measure to permit legacy clients to interact with the server until they can be updated to support more secure communication protocols.
 * @export
 * @enum {string}
 */
export type EnumglobalConfigurationAllowedInsecureTLSProtocolProp = 'sslv3'

