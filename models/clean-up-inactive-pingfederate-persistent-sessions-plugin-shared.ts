/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumcleanUpInactivePingfederatePersistentSessionsPluginSchemaUrn } from './enumclean-up-inactive-pingfederate-persistent-sessions-plugin-schema-urn';

/**
 * 
 * @export
 * @interface CleanUpInactivePingfederatePersistentSessionsPluginShared
 */
export interface CleanUpInactivePingfederatePersistentSessionsPluginShared {
    /**
     * 
     * @type {Array<EnumcleanUpInactivePingfederatePersistentSessionsPluginSchemaUrn>}
     * @memberof CleanUpInactivePingfederatePersistentSessionsPluginShared
     */
    'schemas': Array<EnumcleanUpInactivePingfederatePersistentSessionsPluginSchemaUrn>;
    /**
     * Sessions whose last activity timestamp is older than this offset will be removed.
     * @type {string}
     * @memberof CleanUpInactivePingfederatePersistentSessionsPluginShared
     */
    'expirationOffset': string;
    /**
     * This specifies how often the plugin should check for expired data. It also controls the offset of peer servers (see the peer-server-priority-index for more information).
     * @type {string}
     * @memberof CleanUpInactivePingfederatePersistentSessionsPluginShared
     */
    'pollingInterval'?: string;
    /**
     * In a replicated environment, this determines the order in which peer servers should attempt to purge data.
     * @type {number}
     * @memberof CleanUpInactivePingfederatePersistentSessionsPluginShared
     */
    'peerServerPriorityIndex'?: number;
    /**
     * Only entries located within the subtree specified by this base DN are eligible for purging.
     * @type {string}
     * @memberof CleanUpInactivePingfederatePersistentSessionsPluginShared
     */
    'baseDN'?: string;
    /**
     * This setting smooths out the performance impact on the server by throttling the purging to the specified maximum number of updates per second. To avoid a large backlog, this value should be set comfortably above the average rate that expired data is generated. When purge-behavior is set to subtree-delete-entries, then deletion of the entire subtree is considered a single update for the purposes of throttling.
     * @type {number}
     * @memberof CleanUpInactivePingfederatePersistentSessionsPluginShared
     */
    'maxUpdatesPerSecond'?: number;
    /**
     * The number of threads used to delete expired entries.
     * @type {number}
     * @memberof CleanUpInactivePingfederatePersistentSessionsPluginShared
     */
    'numDeleteThreads'?: number;
    /**
     * Indicates whether the plug-in is enabled for use.
     * @type {boolean}
     * @memberof CleanUpInactivePingfederatePersistentSessionsPluginShared
     */
    'enabled': boolean;
}

