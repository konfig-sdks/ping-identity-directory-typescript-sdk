/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { AddAggregateSearchEntryCriteriaRequest } from './add-aggregate-search-entry-criteria-request';
import { AddSimpleSearchEntryCriteriaRequest } from './add-simple-search-entry-criteria-request';
import { AddThirdPartySearchEntryCriteriaRequest } from './add-third-party-search-entry-criteria-request';
import { EnumthirdPartySearchEntryCriteriaSchemaUrn } from './enumthird-party-search-entry-criteria-schema-urn';

/**
 * @type AddSearchEntryCriteriaRequest
 * @export
 */
export type AddSearchEntryCriteriaRequest = AddAggregateSearchEntryCriteriaRequest | AddSimpleSearchEntryCriteriaRequest | AddThirdPartySearchEntryCriteriaRequest;


