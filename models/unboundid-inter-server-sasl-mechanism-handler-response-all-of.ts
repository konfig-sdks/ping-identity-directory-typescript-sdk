/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumunboundidInterServerSaslMechanismHandlerSchemaUrn } from './enumunboundid-inter-server-sasl-mechanism-handler-schema-urn';

/**
 * 
 * @export
 * @interface UnboundidInterServerSaslMechanismHandlerResponseAllOf
 */
export interface UnboundidInterServerSaslMechanismHandlerResponseAllOf {
    /**
     * A description for this SASL Mechanism Handler
     * @type {string}
     * @memberof UnboundidInterServerSaslMechanismHandlerResponseAllOf
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumunboundidInterServerSaslMechanismHandlerSchemaUrn>}
     * @memberof UnboundidInterServerSaslMechanismHandlerResponseAllOf
     */
    'schemas'?: Array<EnumunboundidInterServerSaslMechanismHandlerSchemaUrn>;
    /**
     * Name of the SASL Mechanism Handler
     * @type {string}
     * @memberof UnboundidInterServerSaslMechanismHandlerResponseAllOf
     */
    'id'?: string;
    /**
     * Indicates whether the SASL mechanism handler is enabled for use.
     * @type {boolean}
     * @memberof UnboundidInterServerSaslMechanismHandlerResponseAllOf
     */
    'enabled'?: boolean;
}

