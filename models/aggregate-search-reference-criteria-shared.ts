/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumaggregateSearchReferenceCriteriaSchemaUrn } from './enumaggregate-search-reference-criteria-schema-urn';

/**
 * 
 * @export
 * @interface AggregateSearchReferenceCriteriaShared
 */
export interface AggregateSearchReferenceCriteriaShared {
    /**
     * A description for this Search Reference Criteria
     * @type {string}
     * @memberof AggregateSearchReferenceCriteriaShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumaggregateSearchReferenceCriteriaSchemaUrn>}
     * @memberof AggregateSearchReferenceCriteriaShared
     */
    'schemas': Array<EnumaggregateSearchReferenceCriteriaSchemaUrn>;
    /**
     * Specifies a search reference criteria object that must match the associated search result reference in order to match the aggregate search reference criteria. If one or more all-included search reference criteria objects are provided, then a search result reference must match all of them in order to match the aggregate search reference criteria.
     * @type {Array<string>}
     * @memberof AggregateSearchReferenceCriteriaShared
     */
    'allIncludedSearchReferenceCriteria'?: Array<string>;
    /**
     * Specifies a search reference criteria object that may match the associated search result reference in order to match the aggregate search reference criteria. If one or more any-included search reference criteria objects are provided, then a search result reference must match at least one of them in order to match the aggregate search reference criteria.
     * @type {Array<string>}
     * @memberof AggregateSearchReferenceCriteriaShared
     */
    'anyIncludedSearchReferenceCriteria'?: Array<string>;
    /**
     * Specifies a search reference criteria object that should not match the associated search result reference in order to match the aggregate search reference criteria. If one or more not-all-included search reference criteria objects are provided, then a search result reference must not match all of them (that is, it may match zero or more of them, but it must not match all of them) in order to match the aggregate search reference criteria.
     * @type {Array<string>}
     * @memberof AggregateSearchReferenceCriteriaShared
     */
    'notAllIncludedSearchReferenceCriteria'?: Array<string>;
    /**
     * Specifies a search reference criteria object that must not match the associated search result reference in order to match the aggregate search reference criteria. If one or more none-included search reference criteria objects are provided, then a search result reference must not match any of them in order to match the aggregate search reference criteria.
     * @type {Array<string>}
     * @memberof AggregateSearchReferenceCriteriaShared
     */
    'noneIncludedSearchReferenceCriteria'?: Array<string>;
}

