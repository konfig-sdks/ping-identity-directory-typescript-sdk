/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumthirdPartyOtpDeliveryMechanismSchemaUrn } from './enumthird-party-otp-delivery-mechanism-schema-urn';

/**
 * 
 * @export
 * @interface ThirdPartyOtpDeliveryMechanismShared
 */
export interface ThirdPartyOtpDeliveryMechanismShared {
    /**
     * A description for this OTP Delivery Mechanism
     * @type {string}
     * @memberof ThirdPartyOtpDeliveryMechanismShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumthirdPartyOtpDeliveryMechanismSchemaUrn>}
     * @memberof ThirdPartyOtpDeliveryMechanismShared
     */
    'schemas': Array<EnumthirdPartyOtpDeliveryMechanismSchemaUrn>;
    /**
     * The fully-qualified name of the Java class providing the logic for the Third Party OTP Delivery Mechanism.
     * @type {string}
     * @memberof ThirdPartyOtpDeliveryMechanismShared
     */
    'extensionClass': string;
    /**
     * The set of arguments used to customize the behavior for the Third Party OTP Delivery Mechanism. Each configuration property should be given in the form \'name=value\'.
     * @type {Array<string>}
     * @memberof ThirdPartyOtpDeliveryMechanismShared
     */
    'extensionArgument'?: Array<string>;
    /**
     * Indicates whether this OTP Delivery Mechanism is enabled for use in the server.
     * @type {boolean}
     * @memberof ThirdPartyOtpDeliveryMechanismShared
     */
    'enabled': boolean;
}

