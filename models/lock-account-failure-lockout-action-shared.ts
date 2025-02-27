/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumlockAccountFailureLockoutActionSchemaUrn } from './enumlock-account-failure-lockout-action-schema-urn';

/**
 * 
 * @export
 * @interface LockAccountFailureLockoutActionShared
 */
export interface LockAccountFailureLockoutActionShared {
    /**
     * A description for this Failure Lockout Action
     * @type {string}
     * @memberof LockAccountFailureLockoutActionShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumlockAccountFailureLockoutActionSchemaUrn>}
     * @memberof LockAccountFailureLockoutActionShared
     */
    'schemas': Array<EnumlockAccountFailureLockoutActionSchemaUrn>;
}

