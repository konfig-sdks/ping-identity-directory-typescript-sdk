/* tslint:disable */
/* eslint-disable */
/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/

import globalAxios, { AxiosPromise, AxiosInstance, AxiosRequestConfig } from 'axios';
import { Configuration } from '../configuration';
// Some imports not used depending on template conditions
// @ts-ignore
import { DUMMY_BASE_URL, assertParamExists, setApiKeyToObject, setBasicAuthToObject, setBearerAuthToObject, setSearchParams, serializeDataIfNeeded, toPathString, createRequestFunction, isBrowser } from '../common';
// @ts-ignore
import { BASE_PATH, COLLECTION_FORMATS, RequestArgs, BaseAPI, RequiredError } from '../base';
// @ts-ignore
import { AddRecurringTask200Response } from '../models';
// @ts-ignore
import { AddRecurringTaskRequest } from '../models';
// @ts-ignore
import { EnumrecurringTaskSecurityLevelProp } from '../models';
// @ts-ignore
import { EnumrecurringTaskTaskCompletionStateForNonzeroExitCodeProp } from '../models';
// @ts-ignore
import { EnumrecurringTaskTaskReturnStateIfTimeoutIsEncounteredProp } from '../models';
// @ts-ignore
import { EnumrecurringTaskTimestampFormatProp } from '../models';
// @ts-ignore
import { EnumthirdPartyRecurringTaskSchemaUrn } from '../models';
// @ts-ignore
import { Operation } from '../models';
// @ts-ignore
import { RecurringTaskListResponse } from '../models';
// @ts-ignore
import { UpdateRequest } from '../models';
import { paginate } from "../pagination/paginate";
import type * as buffer from "buffer"
import { requestBeforeHook } from '../requestBeforeHook';
/**
 * RecurringTaskApi - axios parameter creator
 * @export
 */
export const RecurringTaskApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Add a new Recurring Task to the config
         * @param {AddRecurringTaskRequest} addRecurringTaskRequest Create a new Recurring Task in the config
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewConfig: async (addRecurringTaskRequest: AddRecurringTaskRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'addRecurringTaskRequest' is not null or undefined
            assertParamExists('addNewConfig', 'addRecurringTaskRequest', addRecurringTaskRequest)
            const localVarPath = `/recurring-tasks`;
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            const localVarUrlObj = new URL(localVarPath, DUMMY_BASE_URL);
            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }

            const localVarRequestOptions: AxiosRequestConfig = { method: 'POST', ...baseOptions, ...options};
            const localVarHeaderParameter = configuration && !isBrowser() ? { "User-Agent": configuration.userAgent } : {} as any;
            const localVarQueryParameter = {} as any;

            // authentication basicAuth required
            // http basic authentication required
            setBasicAuthToObject(localVarRequestOptions, configuration)

    
            localVarHeaderParameter['Content-Type'] = 'application/json';


            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers};
            requestBeforeHook({
                requestBody: addRecurringTaskRequest,
                queryParameters: localVarQueryParameter,
                requestConfig: localVarRequestOptions,
                path: localVarPath,
                configuration,
                pathTemplate: '/recurring-tasks',
                httpMethod: 'POST'
            });
            localVarRequestOptions.data = serializeDataIfNeeded(addRecurringTaskRequest, localVarRequestOptions, configuration)

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            return {
                url: toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        },
        /**
         * 
         * @summary Delete a Recurring Task
         * @param {string} recurringTaskName Name of the Recurring Task
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deleteRecurringTask: async (recurringTaskName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'recurringTaskName' is not null or undefined
            assertParamExists('deleteRecurringTask', 'recurringTaskName', recurringTaskName)
            const localVarPath = `/recurring-tasks/{recurring-task-name}`
                .replace(`{${"recurring-task-name"}}`, encodeURIComponent(String(recurringTaskName !== undefined ? recurringTaskName : `-recurring-task-name-`)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            const localVarUrlObj = new URL(localVarPath, DUMMY_BASE_URL);
            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }

            const localVarRequestOptions: AxiosRequestConfig = { method: 'DELETE', ...baseOptions, ...options};
            const localVarHeaderParameter = configuration && !isBrowser() ? { "User-Agent": configuration.userAgent } : {} as any;
            const localVarQueryParameter = {} as any;

            // authentication basicAuth required
            // http basic authentication required
            setBasicAuthToObject(localVarRequestOptions, configuration)

    
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers};
            requestBeforeHook({
                queryParameters: localVarQueryParameter,
                requestConfig: localVarRequestOptions,
                path: localVarPath,
                configuration,
                pathTemplate: '/recurring-tasks/{recurring-task-name}',
                httpMethod: 'DELETE'
            });

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            return {
                url: toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        },
        /**
         * 
         * @summary Returns a single Recurring Task
         * @param {string} recurringTaskName Name of the Recurring Task
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getSingleTask: async (recurringTaskName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'recurringTaskName' is not null or undefined
            assertParamExists('getSingleTask', 'recurringTaskName', recurringTaskName)
            const localVarPath = `/recurring-tasks/{recurring-task-name}`
                .replace(`{${"recurring-task-name"}}`, encodeURIComponent(String(recurringTaskName !== undefined ? recurringTaskName : `-recurring-task-name-`)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            const localVarUrlObj = new URL(localVarPath, DUMMY_BASE_URL);
            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }

            const localVarRequestOptions: AxiosRequestConfig = { method: 'GET', ...baseOptions, ...options};
            const localVarHeaderParameter = configuration && !isBrowser() ? { "User-Agent": configuration.userAgent } : {} as any;
            const localVarQueryParameter = {} as any;

            // authentication basicAuth required
            // http basic authentication required
            setBasicAuthToObject(localVarRequestOptions, configuration)

    
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers};
            requestBeforeHook({
                queryParameters: localVarQueryParameter,
                requestConfig: localVarRequestOptions,
                path: localVarPath,
                configuration,
                pathTemplate: '/recurring-tasks/{recurring-task-name}',
                httpMethod: 'GET'
            });

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            return {
                url: toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        },
        /**
         * 
         * @summary Returns a list of all Recurring Task objects
         * @param {string} [filter] SCIM filter
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        listObjects: async (filter?: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            const localVarPath = `/recurring-tasks`;
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            const localVarUrlObj = new URL(localVarPath, DUMMY_BASE_URL);
            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }

            const localVarRequestOptions: AxiosRequestConfig = { method: 'GET', ...baseOptions, ...options};
            const localVarHeaderParameter = configuration && !isBrowser() ? { "User-Agent": configuration.userAgent } : {} as any;
            const localVarQueryParameter = {} as any;

            // authentication basicAuth required
            // http basic authentication required
            setBasicAuthToObject(localVarRequestOptions, configuration)
            if (filter !== undefined) {
                localVarQueryParameter['filter'] = filter;
            }


    
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers};
            requestBeforeHook({
                queryParameters: localVarQueryParameter,
                requestConfig: localVarRequestOptions,
                path: localVarPath,
                configuration,
                pathTemplate: '/recurring-tasks',
                httpMethod: 'GET'
            });

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            return {
                url: toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        },
        /**
         * 
         * @summary Update an existing Recurring Task by name
         * @param {string} recurringTaskName Name of the Recurring Task
         * @param {UpdateRequest} updateRequest Update an existing Recurring Task
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName: async (recurringTaskName: string, updateRequest: UpdateRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'recurringTaskName' is not null or undefined
            assertParamExists('updateByName', 'recurringTaskName', recurringTaskName)
            // verify required parameter 'updateRequest' is not null or undefined
            assertParamExists('updateByName', 'updateRequest', updateRequest)
            const localVarPath = `/recurring-tasks/{recurring-task-name}`
                .replace(`{${"recurring-task-name"}}`, encodeURIComponent(String(recurringTaskName !== undefined ? recurringTaskName : `-recurring-task-name-`)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            const localVarUrlObj = new URL(localVarPath, DUMMY_BASE_URL);
            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }

            const localVarRequestOptions: AxiosRequestConfig = { method: 'PATCH', ...baseOptions, ...options};
            const localVarHeaderParameter = configuration && !isBrowser() ? { "User-Agent": configuration.userAgent } : {} as any;
            const localVarQueryParameter = {} as any;

            // authentication basicAuth required
            // http basic authentication required
            setBasicAuthToObject(localVarRequestOptions, configuration)

    
            localVarHeaderParameter['Content-Type'] = 'application/json';


            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers};
            requestBeforeHook({
                requestBody: updateRequest,
                queryParameters: localVarQueryParameter,
                requestConfig: localVarRequestOptions,
                path: localVarPath,
                configuration,
                pathTemplate: '/recurring-tasks/{recurring-task-name}',
                httpMethod: 'PATCH'
            });
            localVarRequestOptions.data = serializeDataIfNeeded(updateRequest, localVarRequestOptions, configuration)

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            return {
                url: toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        },
    }
};

/**
 * RecurringTaskApi - functional programming interface
 * @export
 */
export const RecurringTaskApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = RecurringTaskApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Add a new Recurring Task to the config
         * @param {RecurringTaskApiAddNewConfigRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async addNewConfig(requestParameters: RecurringTaskApiAddNewConfigRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<AddRecurringTask200Response>> {
            const addRecurringTaskRequest: AddRecurringTaskRequest = requestParameters;
            const localVarAxiosArgs = await localVarAxiosParamCreator.addNewConfig(addRecurringTaskRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Delete a Recurring Task
         * @param {RecurringTaskApiDeleteRecurringTaskRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async deleteRecurringTask(requestParameters: RecurringTaskApiDeleteRecurringTaskRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<void>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.deleteRecurringTask(requestParameters.recurringTaskName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a single Recurring Task
         * @param {RecurringTaskApiGetSingleTaskRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async getSingleTask(requestParameters: RecurringTaskApiGetSingleTaskRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<AddRecurringTask200Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.getSingleTask(requestParameters.recurringTaskName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a list of all Recurring Task objects
         * @param {RecurringTaskApiListObjectsRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async listObjects(requestParameters: RecurringTaskApiListObjectsRequest = {}, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<RecurringTaskListResponse>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.listObjects(requestParameters.filter, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Update an existing Recurring Task by name
         * @param {RecurringTaskApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async updateByName(requestParameters: RecurringTaskApiUpdateByNameRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<AddRecurringTask200Response>> {
            const updateRequest: UpdateRequest = {
                operations: requestParameters.operations
            };
            const localVarAxiosArgs = await localVarAxiosParamCreator.updateByName(requestParameters.recurringTaskName, updateRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * RecurringTaskApi - factory interface
 * @export
 */
export const RecurringTaskApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = RecurringTaskApiFp(configuration)
    return {
        /**
         * 
         * @summary Add a new Recurring Task to the config
         * @param {RecurringTaskApiAddNewConfigRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewConfig(requestParameters: RecurringTaskApiAddNewConfigRequest, options?: AxiosRequestConfig): AxiosPromise<AddRecurringTask200Response> {
            return localVarFp.addNewConfig(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete a Recurring Task
         * @param {RecurringTaskApiDeleteRecurringTaskRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deleteRecurringTask(requestParameters: RecurringTaskApiDeleteRecurringTaskRequest, options?: AxiosRequestConfig): AxiosPromise<void> {
            return localVarFp.deleteRecurringTask(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a single Recurring Task
         * @param {RecurringTaskApiGetSingleTaskRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getSingleTask(requestParameters: RecurringTaskApiGetSingleTaskRequest, options?: AxiosRequestConfig): AxiosPromise<AddRecurringTask200Response> {
            return localVarFp.getSingleTask(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a list of all Recurring Task objects
         * @param {RecurringTaskApiListObjectsRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        listObjects(requestParameters: RecurringTaskApiListObjectsRequest = {}, options?: AxiosRequestConfig): AxiosPromise<RecurringTaskListResponse> {
            return localVarFp.listObjects(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Update an existing Recurring Task by name
         * @param {RecurringTaskApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName(requestParameters: RecurringTaskApiUpdateByNameRequest, options?: AxiosRequestConfig): AxiosPromise<AddRecurringTask200Response> {
            return localVarFp.updateByName(requestParameters, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * Request parameters for addNewConfig operation in RecurringTaskApi.
 * @export
 * @interface RecurringTaskApiAddNewConfigRequest
 */
export type RecurringTaskApiAddNewConfigRequest = {
    
} & AddRecurringTaskRequest

/**
 * Request parameters for deleteRecurringTask operation in RecurringTaskApi.
 * @export
 * @interface RecurringTaskApiDeleteRecurringTaskRequest
 */
export type RecurringTaskApiDeleteRecurringTaskRequest = {
    
    /**
    * Name of the Recurring Task
    * @type {string}
    * @memberof RecurringTaskApiDeleteRecurringTask
    */
    readonly recurringTaskName: string
    
}

/**
 * Request parameters for getSingleTask operation in RecurringTaskApi.
 * @export
 * @interface RecurringTaskApiGetSingleTaskRequest
 */
export type RecurringTaskApiGetSingleTaskRequest = {
    
    /**
    * Name of the Recurring Task
    * @type {string}
    * @memberof RecurringTaskApiGetSingleTask
    */
    readonly recurringTaskName: string
    
}

/**
 * Request parameters for listObjects operation in RecurringTaskApi.
 * @export
 * @interface RecurringTaskApiListObjectsRequest
 */
export type RecurringTaskApiListObjectsRequest = {
    
    /**
    * SCIM filter
    * @type {string}
    * @memberof RecurringTaskApiListObjects
    */
    readonly filter?: string
    
}

/**
 * Request parameters for updateByName operation in RecurringTaskApi.
 * @export
 * @interface RecurringTaskApiUpdateByNameRequest
 */
export type RecurringTaskApiUpdateByNameRequest = {
    
    /**
    * Name of the Recurring Task
    * @type {string}
    * @memberof RecurringTaskApiUpdateByName
    */
    readonly recurringTaskName: string
    
} & UpdateRequest

/**
 * RecurringTaskApiGenerated - object-oriented interface
 * @export
 * @class RecurringTaskApiGenerated
 * @extends {BaseAPI}
 */
export class RecurringTaskApiGenerated extends BaseAPI {
    /**
     * 
     * @summary Add a new Recurring Task to the config
     * @param {RecurringTaskApiAddNewConfigRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof RecurringTaskApiGenerated
     */
    public addNewConfig(requestParameters: RecurringTaskApiAddNewConfigRequest, options?: AxiosRequestConfig) {
        return RecurringTaskApiFp(this.configuration).addNewConfig(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete a Recurring Task
     * @param {RecurringTaskApiDeleteRecurringTaskRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof RecurringTaskApiGenerated
     */
    public deleteRecurringTask(requestParameters: RecurringTaskApiDeleteRecurringTaskRequest, options?: AxiosRequestConfig) {
        return RecurringTaskApiFp(this.configuration).deleteRecurringTask(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a single Recurring Task
     * @param {RecurringTaskApiGetSingleTaskRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof RecurringTaskApiGenerated
     */
    public getSingleTask(requestParameters: RecurringTaskApiGetSingleTaskRequest, options?: AxiosRequestConfig) {
        return RecurringTaskApiFp(this.configuration).getSingleTask(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a list of all Recurring Task objects
     * @param {RecurringTaskApiListObjectsRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof RecurringTaskApiGenerated
     */
    public listObjects(requestParameters: RecurringTaskApiListObjectsRequest = {}, options?: AxiosRequestConfig) {
        return RecurringTaskApiFp(this.configuration).listObjects(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Update an existing Recurring Task by name
     * @param {RecurringTaskApiUpdateByNameRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof RecurringTaskApiGenerated
     */
    public updateByName(requestParameters: RecurringTaskApiUpdateByNameRequest, options?: AxiosRequestConfig) {
        return RecurringTaskApiFp(this.configuration).updateByName(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }
}
