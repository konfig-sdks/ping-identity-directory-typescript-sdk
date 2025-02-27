/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { AddThirdPartyPostLdifExportTaskProcessorRequest } from './add-third-party-post-ldif-export-task-processor-request';
import { AddUploadToS3PostLdifExportTaskProcessorRequest } from './add-upload-to-s3-post-ldif-export-task-processor-request';
import { EnumthirdPartyPostLdifExportTaskProcessorSchemaUrn } from './enumthird-party-post-ldif-export-task-processor-schema-urn';

/**
 * @type AddPostLdifExportTaskProcessorRequest
 * @export
 */
export type AddPostLdifExportTaskProcessorRequest = AddThirdPartyPostLdifExportTaskProcessorRequest | AddUploadToS3PostLdifExportTaskProcessorRequest;


