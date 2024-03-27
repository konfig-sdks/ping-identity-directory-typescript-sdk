/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumhighThroughputWorkQueueSchemaUrn } from './enumhigh-throughput-work-queue-schema-urn';

/**
 * 
 * @export
 * @interface HighThroughputWorkQueueResponseAllOf
 */
export interface HighThroughputWorkQueueResponseAllOf {
    /**
     * 
     * @type {Array<EnumhighThroughputWorkQueueSchemaUrn>}
     * @memberof HighThroughputWorkQueueResponseAllOf
     */
    'schemas'?: Array<EnumhighThroughputWorkQueueSchemaUrn>;
    /**
     * Specifies the total number of worker threads that should be used within the server in order to process requested operations. The worker threads will be split evenly across all of the configured queues.
     * @type {number}
     * @memberof HighThroughputWorkQueueResponseAllOf
     */
    'numWorkerThreads'?: number;
    /**
     * Specifies the number of worker threads that should be used within the server to process write (add, delete, modify, and modify DN) operations. If this is specified, then separate sets of worker threads will be used for processing read and write operations, and the value of the num-worker-threads property will reflect the number of threads to use to process read operations.
     * @type {number}
     * @memberof HighThroughputWorkQueueResponseAllOf
     */
    'numWriteWorkerThreads'?: number;
    /**
     * Specifies the number of worker threads that should be used to process operations as part of an administrative session. These threads may be reserved only for special use by management applications like dsconfig, the administration console, and other administrative tools, so that these applications may be used to diagnose problems and take any necessary corrective action even if all \"normal\" worker threads are busy processing other requests.
     * @type {number}
     * @memberof HighThroughputWorkQueueResponseAllOf
     */
    'numAdministrativeSessionWorkerThreads'?: number;
    /**
     * Specifies the number of blocking queues that should be maintained. A value of zero indicates that the server should attempt to automatically select an optimal value (one queue for every two worker threads).
     * @type {number}
     * @memberof HighThroughputWorkQueueResponseAllOf
     */
    'numQueues'?: number;
    /**
     * Specifies the number of blocking queues that should be maintained for write operations. This will only be used if a value is specified for the num-write-worker-threads property, in which case the num-queues property will specify the number of queues for read operations. Otherwise, all operations will be processed by a common set of worker threads and the value of the num-queues property will specify the number of queues for all types of operations.
     * @type {number}
     * @memberof HighThroughputWorkQueueResponseAllOf
     */
    'numWriteQueues'?: number;
    /**
     * Specifies the maximum number of pending operations that may be held in any of the queues at any given time. The total number of pending requests may be as large as this value times the total number of queues.
     * @type {number}
     * @memberof HighThroughputWorkQueueResponseAllOf
     */
    'maxWorkQueueCapacity'?: number;
    /**
     * Specifies the maximum length of time that the connection handler should be allowed to wait to enqueue a request if the work queue is full. If the attempt to enqueue an operation does not succeed within this period of time, then the operation will be rejected and an error response will be returned to the client. A value of zero indicates that operations should be rejected immediately if the work queue is already at its maximum capacity.
     * @type {string}
     * @memberof HighThroughputWorkQueueResponseAllOf
     */
    'maxOfferTime'?: string;
    /**
     * Indicates whether the work queue should monitor the length of time that operations are held in the queue. When enabled the queue time will be included with access log messages as \"qtime\" in milliseconds.
     * @type {boolean}
     * @memberof HighThroughputWorkQueueResponseAllOf
     */
    'monitorQueueTime'?: boolean;
    /**
     * Specifies the maximum length of time that an operation should be allowed to wait on the work queue. If an operation has been waiting on the queue longer than this period of time, then it will receive an immediate failure result rather than being processed once it has been handed off to a worker thread. A value of zero seconds indicates that there should not be any maximum queue time imposed. This setting will only be used if the monitor-queue-time property has a value of true.
     * @type {string}
     * @memberof HighThroughputWorkQueueResponseAllOf
     */
    'maxQueueTime'?: string;
    /**
     * The interval that the work queue should use when checking for potentially expensive operations. If at least expensive-operation-minimum-concurrent-count worker threads are found to be processing the same operation on two consecutive polls separated by this time interval (i.e., the worker thread has been processing that operation for at least this length of time, and potentially up to twice this length of time), then a stack trace of all running threads will be written to a file for analysis to provide potentially useful information that may help better understand the reason it is taking so long. It may be that the operation is simply an expensive one to process, but there may be other external factors (e.g., a database checkpoint, a log rotation, lock contention, etc.) that could be to blame. This option is primarily intended for debugging purposes and should generally be used under the direction of Ping Identity support.
     * @type {string}
     * @memberof HighThroughputWorkQueueResponseAllOf
     */
    'expensiveOperationCheckInterval'?: string;
    /**
     * The minimum number of concurrent expensive operations that should be detected to trigger dumping stack traces for all threads. If at least this number of worker threads are seen processing the same operations in two consecutive intervals, then the server will dump a stack trace of all threads to a file. This option is primarily intended for debugging purposes and should generally be used under the direction of Ping Identity support.
     * @type {number}
     * @memberof HighThroughputWorkQueueResponseAllOf
     */
    'expensiveOperationMinimumConcurrentCount'?: number;
    /**
     * The minimum length of time that should be required to pass after dumping stack trace information for all threads before the server should be allowed to create a second dump. This will help prevent the server from dumping stack traces too frequently and eventually consuming all available disk space with stack trace log output. This option is primarily intended for debugging purposes and should generally be used under the direction of Ping Identity support.
     * @type {string}
     * @memberof HighThroughputWorkQueueResponseAllOf
     */
    'expensiveOperationMinimumDumpInterval'?: string;
}

