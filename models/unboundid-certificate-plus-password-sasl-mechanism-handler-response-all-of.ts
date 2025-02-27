/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumunboundidCertificatePlusPasswordSaslMechanismHandlerSchemaUrn } from './enumunboundid-certificate-plus-password-sasl-mechanism-handler-schema-urn';

/**
 * 
 * @export
 * @interface UnboundidCertificatePlusPasswordSaslMechanismHandlerResponseAllOf
 */
export interface UnboundidCertificatePlusPasswordSaslMechanismHandlerResponseAllOf {
    /**
     * A description for this SASL Mechanism Handler
     * @type {string}
     * @memberof UnboundidCertificatePlusPasswordSaslMechanismHandlerResponseAllOf
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumunboundidCertificatePlusPasswordSaslMechanismHandlerSchemaUrn>}
     * @memberof UnboundidCertificatePlusPasswordSaslMechanismHandlerResponseAllOf
     */
    'schemas'?: Array<EnumunboundidCertificatePlusPasswordSaslMechanismHandlerSchemaUrn>;
    /**
     * Name of the SASL Mechanism Handler
     * @type {string}
     * @memberof UnboundidCertificatePlusPasswordSaslMechanismHandlerResponseAllOf
     */
    'id'?: string;
    /**
     * The certificate mapper that will be used to identify the target user based on the certificate that was presented to the server.
     * @type {string}
     * @memberof UnboundidCertificatePlusPasswordSaslMechanismHandlerResponseAllOf
     */
    'certificateMapper'?: string;
    /**
     * Indicates whether the SASL mechanism handler is enabled for use.
     * @type {boolean}
     * @memberof UnboundidCertificatePlusPasswordSaslMechanismHandlerResponseAllOf
     */
    'enabled'?: boolean;
}

