/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumlastAccessTimeUncachedEntryCriteriaSchemaUrn } from './enumlast-access-time-uncached-entry-criteria-schema-urn';

/**
 * 
 * @export
 * @interface LastAccessTimeUncachedEntryCriteriaShared
 */
export interface LastAccessTimeUncachedEntryCriteriaShared {
    /**
     * A description for this Uncached Entry Criteria
     * @type {string}
     * @memberof LastAccessTimeUncachedEntryCriteriaShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumlastAccessTimeUncachedEntryCriteriaSchemaUrn>}
     * @memberof LastAccessTimeUncachedEntryCriteriaShared
     */
    'schemas': Array<EnumlastAccessTimeUncachedEntryCriteriaSchemaUrn>;
    /**
     * Specifies the maximum length of time that has passed since an entry was last accessed that it should still be included in the id2entry database. Entries that have not been accessed in more than this length of time may be written into the uncached-id2entry database.
     * @type {string}
     * @memberof LastAccessTimeUncachedEntryCriteriaShared
     */
    'accessTimeThreshold': string;
    /**
     * Indicates whether this Uncached Entry Criteria is enabled for use in the server.
     * @type {boolean}
     * @memberof LastAccessTimeUncachedEntryCriteriaShared
     */
    'enabled': boolean;
}

