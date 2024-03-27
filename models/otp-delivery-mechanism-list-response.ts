/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { AddOtpDeliveryMechanism200Response } from './add-otp-delivery-mechanism200-response';

/**
 * 
 * @export
 * @interface OtpDeliveryMechanismListResponse
 */
export interface OtpDeliveryMechanismListResponse {
    /**
     * 
     * @type {Array<string>}
     * @memberof OtpDeliveryMechanismListResponse
     */
    'schemas'?: Array<string>;
    /**
     * 
     * @type {number}
     * @memberof OtpDeliveryMechanismListResponse
     */
    'totalResults'?: number;
    /**
     * 
     * @type {Array<AddOtpDeliveryMechanism200Response>}
     * @memberof OtpDeliveryMechanismListResponse
     */
    'Resources'?: Array<AddOtpDeliveryMechanism200Response>;
}

