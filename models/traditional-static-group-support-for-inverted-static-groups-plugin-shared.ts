/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumpluginReadOperationSupportProp } from './enumplugin-read-operation-support-prop';
import { EnumpluginTraditionalStaticGroupObjectClassProp } from './enumplugin-traditional-static-group-object-class-prop';
import { EnumtraditionalStaticGroupSupportForInvertedStaticGroupsPluginSchemaUrn } from './enumtraditional-static-group-support-for-inverted-static-groups-plugin-schema-urn';

/**
 * 
 * @export
 * @interface TraditionalStaticGroupSupportForInvertedStaticGroupsPluginShared
 */
export interface TraditionalStaticGroupSupportForInvertedStaticGroupsPluginShared {
    /**
     * A description for this Plugin
     * @type {string}
     * @memberof TraditionalStaticGroupSupportForInvertedStaticGroupsPluginShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumtraditionalStaticGroupSupportForInvertedStaticGroupsPluginSchemaUrn>}
     * @memberof TraditionalStaticGroupSupportForInvertedStaticGroupsPluginShared
     */
    'schemas': Array<EnumtraditionalStaticGroupSupportForInvertedStaticGroupsPluginSchemaUrn>;
    /**
     * The object class that defines the type of traditional static group that this plugin will attempt to emulate for inverted static groups.
     * @type {EnumpluginTraditionalStaticGroupObjectClassProp}
     * @memberof TraditionalStaticGroupSupportForInvertedStaticGroupsPluginShared
     */
    'traditionalStaticGroupObjectClass'?: EnumpluginTraditionalStaticGroupObjectClassProp;
    /**
     * An integer property that specifies the maximum number of membership changes that will be supported in a single modify operation. A value of zero indicates that modify operations targeting the group entry should not be permitted to alter the set of members for the group.
     * @type {number}
     * @memberof TraditionalStaticGroupSupportForInvertedStaticGroupsPluginShared
     */
    'maximumMembershipUpdatesPerModify'?: number;
    /**
     * The level of support that the server should offer to allow treating search and compare operations targeting inverted static groups as if they were traditional static groups.
     * @type {EnumpluginReadOperationSupportProp}
     * @memberof TraditionalStaticGroupSupportForInvertedStaticGroupsPluginShared
     */
    'readOperationSupport'?: EnumpluginReadOperationSupportProp;
    /**
     * Indicates whether the plug-in is enabled for use.
     * @type {boolean}
     * @memberof TraditionalStaticGroupSupportForInvertedStaticGroupsPluginShared
     */
    'enabled': boolean;
    /**
     * Indicates whether the plug-in should be invoked for internal operations.
     * @type {boolean}
     * @memberof TraditionalStaticGroupSupportForInvertedStaticGroupsPluginShared
     */
    'invokeForInternalOperations'?: boolean;
}

