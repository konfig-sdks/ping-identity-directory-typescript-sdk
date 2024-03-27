/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumtrustedCertificateSchemaUrn } from './enumtrusted-certificate-schema-urn';

/**
 * 
 * @export
 * @interface TrustedCertificateShared
 */
export interface TrustedCertificateShared {
    /**
     * 
     * @type {Array<EnumtrustedCertificateSchemaUrn>}
     * @memberof TrustedCertificateShared
     */
    'schemas'?: Array<EnumtrustedCertificateSchemaUrn>;
    /**
     * The PEM-encoded X.509v3 certificate.
     * @type {string}
     * @memberof TrustedCertificateShared
     */
    'certificate': string;
}

