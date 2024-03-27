/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { AddGenericRestResourceTypeRequest } from './add-generic-rest-resource-type-request';
import { AddGroupRestResourceTypeRequest } from './add-group-rest-resource-type-request';
import { AddUserRestResourceTypeRequest } from './add-user-rest-resource-type-request';
import { EnumgroupRestResourceTypeSchemaUrn } from './enumgroup-rest-resource-type-schema-urn';

/**
 * @type AddRestResourceTypeRequest
 * @export
 */
export type AddRestResourceTypeRequest = AddGenericRestResourceTypeRequest | AddGroupRestResourceTypeRequest | AddUserRestResourceTypeRequest;


