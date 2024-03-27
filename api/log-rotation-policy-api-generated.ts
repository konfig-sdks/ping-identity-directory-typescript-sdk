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
import { AddLogRotationPolicy200Response } from '../models';
// @ts-ignore
import { AddLogRotationPolicyRequest } from '../models';
// @ts-ignore
import { EnumsizeLimitLogRotationPolicySchemaUrn } from '../models';
// @ts-ignore
import { LogRotationPolicyListResponse } from '../models';
// @ts-ignore
import { Operation } from '../models';
// @ts-ignore
import { UpdateRequest } from '../models';
import { paginate } from "../pagination/paginate";
import type * as buffer from "buffer"
import { requestBeforeHook } from '../requestBeforeHook';
/**
 * LogRotationPolicyApi - axios parameter creator
 * @export
 */
export const LogRotationPolicyApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Add a new Log Rotation Policy to the config
         * @param {AddLogRotationPolicyRequest} addLogRotationPolicyRequest Create a new Log Rotation Policy in the config
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewPolicy: async (addLogRotationPolicyRequest: AddLogRotationPolicyRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'addLogRotationPolicyRequest' is not null or undefined
            assertParamExists('addNewPolicy', 'addLogRotationPolicyRequest', addLogRotationPolicyRequest)
            const localVarPath = `/log-rotation-policies`;
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
                requestBody: addLogRotationPolicyRequest,
                queryParameters: localVarQueryParameter,
                requestConfig: localVarRequestOptions,
                path: localVarPath,
                configuration,
                pathTemplate: '/log-rotation-policies',
                httpMethod: 'POST'
            });
            localVarRequestOptions.data = serializeDataIfNeeded(addLogRotationPolicyRequest, localVarRequestOptions, configuration)

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            return {
                url: toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        },
        /**
         * 
         * @summary Delete a Log Rotation Policy
         * @param {string} logRotationPolicyName Name of the Log Rotation Policy
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deletePolicy: async (logRotationPolicyName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'logRotationPolicyName' is not null or undefined
            assertParamExists('deletePolicy', 'logRotationPolicyName', logRotationPolicyName)
            const localVarPath = `/log-rotation-policies/{log-rotation-policy-name}`
                .replace(`{${"log-rotation-policy-name"}}`, encodeURIComponent(String(logRotationPolicyName !== undefined ? logRotationPolicyName : `-log-rotation-policy-name-`)));
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
                pathTemplate: '/log-rotation-policies/{log-rotation-policy-name}',
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
         * @summary Returns a list of all Log Rotation Policy objects
         * @param {string} [filter] SCIM filter
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getAllLogRotationPolicies: async (filter?: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            const localVarPath = `/log-rotation-policies`;
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
                pathTemplate: '/log-rotation-policies',
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
         * @summary Returns a single Log Rotation Policy
         * @param {string} logRotationPolicyName Name of the Log Rotation Policy
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getSingleLogRotationPolicy: async (logRotationPolicyName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'logRotationPolicyName' is not null or undefined
            assertParamExists('getSingleLogRotationPolicy', 'logRotationPolicyName', logRotationPolicyName)
            const localVarPath = `/log-rotation-policies/{log-rotation-policy-name}`
                .replace(`{${"log-rotation-policy-name"}}`, encodeURIComponent(String(logRotationPolicyName !== undefined ? logRotationPolicyName : `-log-rotation-policy-name-`)));
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
                pathTemplate: '/log-rotation-policies/{log-rotation-policy-name}',
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
         * @summary Update an existing Log Rotation Policy by name
         * @param {string} logRotationPolicyName Name of the Log Rotation Policy
         * @param {UpdateRequest} updateRequest Update an existing Log Rotation Policy
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName: async (logRotationPolicyName: string, updateRequest: UpdateRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'logRotationPolicyName' is not null or undefined
            assertParamExists('updateByName', 'logRotationPolicyName', logRotationPolicyName)
            // verify required parameter 'updateRequest' is not null or undefined
            assertParamExists('updateByName', 'updateRequest', updateRequest)
            const localVarPath = `/log-rotation-policies/{log-rotation-policy-name}`
                .replace(`{${"log-rotation-policy-name"}}`, encodeURIComponent(String(logRotationPolicyName !== undefined ? logRotationPolicyName : `-log-rotation-policy-name-`)));
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
                pathTemplate: '/log-rotation-policies/{log-rotation-policy-name}',
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
 * LogRotationPolicyApi - functional programming interface
 * @export
 */
export const LogRotationPolicyApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = LogRotationPolicyApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Add a new Log Rotation Policy to the config
         * @param {LogRotationPolicyApiAddNewPolicyRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async addNewPolicy(requestParameters: LogRotationPolicyApiAddNewPolicyRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<AddLogRotationPolicy200Response>> {
            const addLogRotationPolicyRequest: AddLogRotationPolicyRequest = requestParameters;
            const localVarAxiosArgs = await localVarAxiosParamCreator.addNewPolicy(addLogRotationPolicyRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Delete a Log Rotation Policy
         * @param {LogRotationPolicyApiDeletePolicyRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async deletePolicy(requestParameters: LogRotationPolicyApiDeletePolicyRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<void>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.deletePolicy(requestParameters.logRotationPolicyName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a list of all Log Rotation Policy objects
         * @param {LogRotationPolicyApiGetAllLogRotationPoliciesRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async getAllLogRotationPolicies(requestParameters: LogRotationPolicyApiGetAllLogRotationPoliciesRequest = {}, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<LogRotationPolicyListResponse>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.getAllLogRotationPolicies(requestParameters.filter, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a single Log Rotation Policy
         * @param {LogRotationPolicyApiGetSingleLogRotationPolicyRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async getSingleLogRotationPolicy(requestParameters: LogRotationPolicyApiGetSingleLogRotationPolicyRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<AddLogRotationPolicy200Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.getSingleLogRotationPolicy(requestParameters.logRotationPolicyName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Update an existing Log Rotation Policy by name
         * @param {LogRotationPolicyApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async updateByName(requestParameters: LogRotationPolicyApiUpdateByNameRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<AddLogRotationPolicy200Response>> {
            const updateRequest: UpdateRequest = {
                operations: requestParameters.operations
            };
            const localVarAxiosArgs = await localVarAxiosParamCreator.updateByName(requestParameters.logRotationPolicyName, updateRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * LogRotationPolicyApi - factory interface
 * @export
 */
export const LogRotationPolicyApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = LogRotationPolicyApiFp(configuration)
    return {
        /**
         * 
         * @summary Add a new Log Rotation Policy to the config
         * @param {LogRotationPolicyApiAddNewPolicyRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewPolicy(requestParameters: LogRotationPolicyApiAddNewPolicyRequest, options?: AxiosRequestConfig): AxiosPromise<AddLogRotationPolicy200Response> {
            return localVarFp.addNewPolicy(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete a Log Rotation Policy
         * @param {LogRotationPolicyApiDeletePolicyRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deletePolicy(requestParameters: LogRotationPolicyApiDeletePolicyRequest, options?: AxiosRequestConfig): AxiosPromise<void> {
            return localVarFp.deletePolicy(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a list of all Log Rotation Policy objects
         * @param {LogRotationPolicyApiGetAllLogRotationPoliciesRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getAllLogRotationPolicies(requestParameters: LogRotationPolicyApiGetAllLogRotationPoliciesRequest = {}, options?: AxiosRequestConfig): AxiosPromise<LogRotationPolicyListResponse> {
            return localVarFp.getAllLogRotationPolicies(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a single Log Rotation Policy
         * @param {LogRotationPolicyApiGetSingleLogRotationPolicyRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getSingleLogRotationPolicy(requestParameters: LogRotationPolicyApiGetSingleLogRotationPolicyRequest, options?: AxiosRequestConfig): AxiosPromise<AddLogRotationPolicy200Response> {
            return localVarFp.getSingleLogRotationPolicy(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Update an existing Log Rotation Policy by name
         * @param {LogRotationPolicyApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName(requestParameters: LogRotationPolicyApiUpdateByNameRequest, options?: AxiosRequestConfig): AxiosPromise<AddLogRotationPolicy200Response> {
            return localVarFp.updateByName(requestParameters, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * Request parameters for addNewPolicy operation in LogRotationPolicyApi.
 * @export
 * @interface LogRotationPolicyApiAddNewPolicyRequest
 */
export type LogRotationPolicyApiAddNewPolicyRequest = {
    
} & AddLogRotationPolicyRequest

/**
 * Request parameters for deletePolicy operation in LogRotationPolicyApi.
 * @export
 * @interface LogRotationPolicyApiDeletePolicyRequest
 */
export type LogRotationPolicyApiDeletePolicyRequest = {
    
    /**
    * Name of the Log Rotation Policy
    * @type {string}
    * @memberof LogRotationPolicyApiDeletePolicy
    */
    readonly logRotationPolicyName: string
    
}

/**
 * Request parameters for getAllLogRotationPolicies operation in LogRotationPolicyApi.
 * @export
 * @interface LogRotationPolicyApiGetAllLogRotationPoliciesRequest
 */
export type LogRotationPolicyApiGetAllLogRotationPoliciesRequest = {
    
    /**
    * SCIM filter
    * @type {string}
    * @memberof LogRotationPolicyApiGetAllLogRotationPolicies
    */
    readonly filter?: string
    
}

/**
 * Request parameters for getSingleLogRotationPolicy operation in LogRotationPolicyApi.
 * @export
 * @interface LogRotationPolicyApiGetSingleLogRotationPolicyRequest
 */
export type LogRotationPolicyApiGetSingleLogRotationPolicyRequest = {
    
    /**
    * Name of the Log Rotation Policy
    * @type {string}
    * @memberof LogRotationPolicyApiGetSingleLogRotationPolicy
    */
    readonly logRotationPolicyName: string
    
}

/**
 * Request parameters for updateByName operation in LogRotationPolicyApi.
 * @export
 * @interface LogRotationPolicyApiUpdateByNameRequest
 */
export type LogRotationPolicyApiUpdateByNameRequest = {
    
    /**
    * Name of the Log Rotation Policy
    * @type {string}
    * @memberof LogRotationPolicyApiUpdateByName
    */
    readonly logRotationPolicyName: string
    
} & UpdateRequest

/**
 * LogRotationPolicyApiGenerated - object-oriented interface
 * @export
 * @class LogRotationPolicyApiGenerated
 * @extends {BaseAPI}
 */
export class LogRotationPolicyApiGenerated extends BaseAPI {
    /**
     * 
     * @summary Add a new Log Rotation Policy to the config
     * @param {LogRotationPolicyApiAddNewPolicyRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof LogRotationPolicyApiGenerated
     */
    public addNewPolicy(requestParameters: LogRotationPolicyApiAddNewPolicyRequest, options?: AxiosRequestConfig) {
        return LogRotationPolicyApiFp(this.configuration).addNewPolicy(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete a Log Rotation Policy
     * @param {LogRotationPolicyApiDeletePolicyRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof LogRotationPolicyApiGenerated
     */
    public deletePolicy(requestParameters: LogRotationPolicyApiDeletePolicyRequest, options?: AxiosRequestConfig) {
        return LogRotationPolicyApiFp(this.configuration).deletePolicy(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a list of all Log Rotation Policy objects
     * @param {LogRotationPolicyApiGetAllLogRotationPoliciesRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof LogRotationPolicyApiGenerated
     */
    public getAllLogRotationPolicies(requestParameters: LogRotationPolicyApiGetAllLogRotationPoliciesRequest = {}, options?: AxiosRequestConfig) {
        return LogRotationPolicyApiFp(this.configuration).getAllLogRotationPolicies(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a single Log Rotation Policy
     * @param {LogRotationPolicyApiGetSingleLogRotationPolicyRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof LogRotationPolicyApiGenerated
     */
    public getSingleLogRotationPolicy(requestParameters: LogRotationPolicyApiGetSingleLogRotationPolicyRequest, options?: AxiosRequestConfig) {
        return LogRotationPolicyApiFp(this.configuration).getSingleLogRotationPolicy(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Update an existing Log Rotation Policy by name
     * @param {LogRotationPolicyApiUpdateByNameRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof LogRotationPolicyApiGenerated
     */
    public updateByName(requestParameters: LogRotationPolicyApiUpdateByNameRequest, options?: AxiosRequestConfig) {
        return LogRotationPolicyApiFp(this.configuration).updateByName(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }
}
