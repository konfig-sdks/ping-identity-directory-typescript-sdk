/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumencryptionSettingsDatabaseAccessibilityMonitorProviderSchemaUrn } from './enumencryption-settings-database-accessibility-monitor-provider-schema-urn';
import { EnummonitorProviderProlongedOutageBehaviorProp } from './enummonitor-provider-prolonged-outage-behavior-prop';

/**
 * 
 * @export
 * @interface EncryptionSettingsDatabaseAccessibilityMonitorProviderShared
 */
export interface EncryptionSettingsDatabaseAccessibilityMonitorProviderShared {
    /**
     * A description for this Monitor Provider
     * @type {string}
     * @memberof EncryptionSettingsDatabaseAccessibilityMonitorProviderShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumencryptionSettingsDatabaseAccessibilityMonitorProviderSchemaUrn>}
     * @memberof EncryptionSettingsDatabaseAccessibilityMonitorProviderShared
     */
    'schemas': Array<EnumencryptionSettingsDatabaseAccessibilityMonitorProviderSchemaUrn>;
    /**
     * The frequency with which this monitor provider should confirm the ability to access the server\'s encryption settings database.
     * @type {string}
     * @memberof EncryptionSettingsDatabaseAccessibilityMonitorProviderShared
     */
    'checkFrequency'?: string;
    /**
     * The minimum length of time that an outage should persist before it is considered a prolonged outage. If an outage lasts at least as long as this duration, then the server will take the action indicated by the prolonged-outage-behavior property.
     * @type {string}
     * @memberof EncryptionSettingsDatabaseAccessibilityMonitorProviderShared
     */
    'prolongedOutageDuration'?: string;
    /**
     * The behavior that the server should exhibit after a prolonged period of time when the encryption settings database remains unreadable.
     * @type {EnummonitorProviderProlongedOutageBehaviorProp}
     * @memberof EncryptionSettingsDatabaseAccessibilityMonitorProviderShared
     */
    'prolongedOutageBehavior'?: EnummonitorProviderProlongedOutageBehaviorProp;
    /**
     * Indicates whether the Monitor Provider is enabled for use.
     * @type {boolean}
     * @memberof EncryptionSettingsDatabaseAccessibilityMonitorProviderShared
     */
    'enabled': boolean;
}

