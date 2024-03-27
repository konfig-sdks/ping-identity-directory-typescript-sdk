/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumcramMd5SaslMechanismHandlerSchemaUrn } from './enumcram-md5-sasl-mechanism-handler-schema-urn';

/**
 * 
 * @export
 * @interface CramMd5SaslMechanismHandlerResponseAllOf
 */
export interface CramMd5SaslMechanismHandlerResponseAllOf {
    /**
     * A description for this SASL Mechanism Handler
     * @type {string}
     * @memberof CramMd5SaslMechanismHandlerResponseAllOf
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumcramMd5SaslMechanismHandlerSchemaUrn>}
     * @memberof CramMd5SaslMechanismHandlerResponseAllOf
     */
    'schemas'?: Array<EnumcramMd5SaslMechanismHandlerSchemaUrn>;
    /**
     * Name of the SASL Mechanism Handler
     * @type {string}
     * @memberof CramMd5SaslMechanismHandlerResponseAllOf
     */
    'id'?: string;
    /**
     * Specifies the name of the identity mapper used with this SASL mechanism handler to match the authentication ID included in the SASL bind request to the corresponding user in the directory.
     * @type {string}
     * @memberof CramMd5SaslMechanismHandlerResponseAllOf
     */
    'identityMapper'?: string;
    /**
     * Indicates whether the SASL mechanism handler is enabled for use.
     * @type {boolean}
     * @memberof CramMd5SaslMechanismHandlerResponseAllOf
     */
    'enabled'?: boolean;
}

