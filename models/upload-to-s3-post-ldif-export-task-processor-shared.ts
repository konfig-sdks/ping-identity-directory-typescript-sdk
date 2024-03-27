/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumuploadToS3PostLdifExportTaskProcessorSchemaUrn } from './enumupload-to-s3-post-ldif-export-task-processor-schema-urn';

/**
 * 
 * @export
 * @interface UploadToS3PostLdifExportTaskProcessorShared
 */
export interface UploadToS3PostLdifExportTaskProcessorShared {
    /**
     * A description for this Post LDIF Export Task Processor
     * @type {string}
     * @memberof UploadToS3PostLdifExportTaskProcessorShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumuploadToS3PostLdifExportTaskProcessorSchemaUrn>}
     * @memberof UploadToS3PostLdifExportTaskProcessorShared
     */
    'schemas': Array<EnumuploadToS3PostLdifExportTaskProcessorSchemaUrn>;
    /**
     * The external server with information to use when interacting with the AWS S3 service.
     * @type {string}
     * @memberof UploadToS3PostLdifExportTaskProcessorShared
     */
    'awsExternalServer': string;
    /**
     * The name of the S3 bucket into which LDIF files should be copied.
     * @type {string}
     * @memberof UploadToS3PostLdifExportTaskProcessorShared
     */
    's3BucketName': string;
    /**
     * The target throughput to attempt to achieve for data transfers to or from S3, in megabits per second.
     * @type {number}
     * @memberof UploadToS3PostLdifExportTaskProcessorShared
     */
    'targetThroughputInMegabitsPerSecond'?: number;
    /**
     * The maximum number of concurrent connections that may be used when transferring data to or from S3.
     * @type {number}
     * @memberof UploadToS3PostLdifExportTaskProcessorShared
     */
    'maximumConcurrentTransferConnections'?: number;
    /**
     * The maximum number of existing files matching the file retention pattern that should be retained in the S3 bucket after successfully uploading a newly exported file.
     * @type {number}
     * @memberof UploadToS3PostLdifExportTaskProcessorShared
     */
    'maximumFileCountToRetain'?: number;
    /**
     * The maximum length of time to retain files matching the file retention pattern that should be retained in the S3 bucket after successfully uploading a newly exported file.
     * @type {string}
     * @memberof UploadToS3PostLdifExportTaskProcessorShared
     */
    'maximumFileAgeToRetain'?: string;
    /**
     * A regular expression pattern that will be used to identify which files are candidates for automatic removal based on the maximum-file-count-to-retain and maximum-file-age-to-retain properties. By default, all files in the bucket will be eligible for removal by retention processing.
     * @type {string}
     * @memberof UploadToS3PostLdifExportTaskProcessorShared
     */
    'fileRetentionPattern'?: string;
    /**
     * Indicates whether the Post LDIF Export Task Processor is enabled for use.
     * @type {boolean}
     * @memberof UploadToS3PostLdifExportTaskProcessorShared
     */
    'enabled': boolean;
}

