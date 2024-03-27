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
import { AddLogRetentionPolicy200Response } from '../models';
// @ts-ignore
import { AddLogRetentionPolicyRequest } from '../models';
// @ts-ignore
import { EnumsizeLimitLogRetentionPolicySchemaUrn } from '../models';
// @ts-ignore
import { LogRetentionPolicyListResponse } from '../models';
// @ts-ignore
import { Operation } from '../models';
// @ts-ignore
import { UpdateRequest } from '../models';
import { paginate } from "../pagination/paginate";
import type * as buffer from "buffer"
import { requestBeforeHook } from '../requestBeforeHook';
/**
 * LogRetentionPolicyApi - axios parameter creator
 * @export
 */
export const LogRetentionPolicyApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Add a new Log Retention Policy to the config
         * @param {AddLogRetentionPolicyRequest} addLogRetentionPolicyRequest Create a new Log Retention Policy in the config
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewLogRetentionPolicy: async (addLogRetentionPolicyRequest: AddLogRetentionPolicyRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'addLogRetentionPolicyRequest' is not null or undefined
            assertParamExists('addNewLogRetentionPolicy', 'addLogRetentionPolicyRequest', addLogRetentionPolicyRequest)
            const localVarPath = `/log-retention-policies`;
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
                requestBody: addLogRetentionPolicyRequest,
                queryParameters: localVarQueryParameter,
                requestConfig: localVarRequestOptions,
                path: localVarPath,
                configuration,
                pathTemplate: '/log-retention-policies',
                httpMethod: 'POST'
            });
            localVarRequestOptions.data = serializeDataIfNeeded(addLogRetentionPolicyRequest, localVarRequestOptions, configuration)

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            return {
                url: toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        },
        /**
         * 
         * @summary Delete a Log Retention Policy
         * @param {string} logRetentionPolicyName Name of the Log Retention Policy
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deleteLogRetentionPolicy: async (logRetentionPolicyName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'logRetentionPolicyName' is not null or undefined
            assertParamExists('deleteLogRetentionPolicy', 'logRetentionPolicyName', logRetentionPolicyName)
            const localVarPath = `/log-retention-policies/{log-retention-policy-name}`
                .replace(`{${"log-retention-policy-name"}}`, encodeURIComponent(String(logRetentionPolicyName !== undefined ? logRetentionPolicyName : `-log-retention-policy-name-`)));
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
                pathTemplate: '/log-retention-policies/{log-retention-policy-name}',
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
         * @summary Returns a single Log Retention Policy
         * @param {string} logRetentionPolicyName Name of the Log Retention Policy
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getSingle: async (logRetentionPolicyName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'logRetentionPolicyName' is not null or undefined
            assertParamExists('getSingle', 'logRetentionPolicyName', logRetentionPolicyName)
            const localVarPath = `/log-retention-policies/{log-retention-policy-name}`
                .replace(`{${"log-retention-policy-name"}}`, encodeURIComponent(String(logRetentionPolicyName !== undefined ? logRetentionPolicyName : `-log-retention-policy-name-`)));
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
                pathTemplate: '/log-retention-policies/{log-retention-policy-name}',
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
         * @summary Returns a list of all Log Retention Policy objects
         * @param {string} [filter] SCIM filter
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        listAllLogRetentionPolicies: async (filter?: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            const localVarPath = `/log-retention-policies`;
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
                pathTemplate: '/log-retention-policies',
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
         * @summary Update an existing Log Retention Policy by name
         * @param {string} logRetentionPolicyName Name of the Log Retention Policy
         * @param {UpdateRequest} updateRequest Update an existing Log Retention Policy
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName: async (logRetentionPolicyName: string, updateRequest: UpdateRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'logRetentionPolicyName' is not null or undefined
            assertParamExists('updateByName', 'logRetentionPolicyName', logRetentionPolicyName)
            // verify required parameter 'updateRequest' is not null or undefined
            assertParamExists('updateByName', 'updateRequest', updateRequest)
            const localVarPath = `/log-retention-policies/{log-retention-policy-name}`
                .replace(`{${"log-retention-policy-name"}}`, encodeURIComponent(String(logRetentionPolicyName !== undefined ? logRetentionPolicyName : `-log-retention-policy-name-`)));
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
                pathTemplate: '/log-retention-policies/{log-retention-policy-name}',
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
 * LogRetentionPolicyApi - functional programming interface
 * @export
 */
export const LogRetentionPolicyApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = LogRetentionPolicyApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Add a new Log Retention Policy to the config
         * @param {LogRetentionPolicyApiAddNewLogRetentionPolicyRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async addNewLogRetentionPolicy(requestParameters: LogRetentionPolicyApiAddNewLogRetentionPolicyRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<AddLogRetentionPolicy200Response>> {
            const addLogRetentionPolicyRequest: AddLogRetentionPolicyRequest = requestParameters;
            const localVarAxiosArgs = await localVarAxiosParamCreator.addNewLogRetentionPolicy(addLogRetentionPolicyRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Delete a Log Retention Policy
         * @param {LogRetentionPolicyApiDeleteLogRetentionPolicyRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async deleteLogRetentionPolicy(requestParameters: LogRetentionPolicyApiDeleteLogRetentionPolicyRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<void>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.deleteLogRetentionPolicy(requestParameters.logRetentionPolicyName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a single Log Retention Policy
         * @param {LogRetentionPolicyApiGetSingleRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async getSingle(requestParameters: LogRetentionPolicyApiGetSingleRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<AddLogRetentionPolicy200Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.getSingle(requestParameters.logRetentionPolicyName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a list of all Log Retention Policy objects
         * @param {LogRetentionPolicyApiListAllLogRetentionPoliciesRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async listAllLogRetentionPolicies(requestParameters: LogRetentionPolicyApiListAllLogRetentionPoliciesRequest = {}, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<LogRetentionPolicyListResponse>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.listAllLogRetentionPolicies(requestParameters.filter, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Update an existing Log Retention Policy by name
         * @param {LogRetentionPolicyApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async updateByName(requestParameters: LogRetentionPolicyApiUpdateByNameRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<AddLogRetentionPolicy200Response>> {
            const updateRequest: UpdateRequest = {
                operations: requestParameters.operations
            };
            const localVarAxiosArgs = await localVarAxiosParamCreator.updateByName(requestParameters.logRetentionPolicyName, updateRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * LogRetentionPolicyApi - factory interface
 * @export
 */
export const LogRetentionPolicyApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = LogRetentionPolicyApiFp(configuration)
    return {
        /**
         * 
         * @summary Add a new Log Retention Policy to the config
         * @param {LogRetentionPolicyApiAddNewLogRetentionPolicyRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewLogRetentionPolicy(requestParameters: LogRetentionPolicyApiAddNewLogRetentionPolicyRequest, options?: AxiosRequestConfig): AxiosPromise<AddLogRetentionPolicy200Response> {
            return localVarFp.addNewLogRetentionPolicy(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete a Log Retention Policy
         * @param {LogRetentionPolicyApiDeleteLogRetentionPolicyRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deleteLogRetentionPolicy(requestParameters: LogRetentionPolicyApiDeleteLogRetentionPolicyRequest, options?: AxiosRequestConfig): AxiosPromise<void> {
            return localVarFp.deleteLogRetentionPolicy(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a single Log Retention Policy
         * @param {LogRetentionPolicyApiGetSingleRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getSingle(requestParameters: LogRetentionPolicyApiGetSingleRequest, options?: AxiosRequestConfig): AxiosPromise<AddLogRetentionPolicy200Response> {
            return localVarFp.getSingle(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a list of all Log Retention Policy objects
         * @param {LogRetentionPolicyApiListAllLogRetentionPoliciesRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        listAllLogRetentionPolicies(requestParameters: LogRetentionPolicyApiListAllLogRetentionPoliciesRequest = {}, options?: AxiosRequestConfig): AxiosPromise<LogRetentionPolicyListResponse> {
            return localVarFp.listAllLogRetentionPolicies(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Update an existing Log Retention Policy by name
         * @param {LogRetentionPolicyApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName(requestParameters: LogRetentionPolicyApiUpdateByNameRequest, options?: AxiosRequestConfig): AxiosPromise<AddLogRetentionPolicy200Response> {
            return localVarFp.updateByName(requestParameters, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * Request parameters for addNewLogRetentionPolicy operation in LogRetentionPolicyApi.
 * @export
 * @interface LogRetentionPolicyApiAddNewLogRetentionPolicyRequest
 */
export type LogRetentionPolicyApiAddNewLogRetentionPolicyRequest = {
    
} & AddLogRetentionPolicyRequest

/**
 * Request parameters for deleteLogRetentionPolicy operation in LogRetentionPolicyApi.
 * @export
 * @interface LogRetentionPolicyApiDeleteLogRetentionPolicyRequest
 */
export type LogRetentionPolicyApiDeleteLogRetentionPolicyRequest = {
    
    /**
    * Name of the Log Retention Policy
    * @type {string}
    * @memberof LogRetentionPolicyApiDeleteLogRetentionPolicy
    */
    readonly logRetentionPolicyName: string
    
}

/**
 * Request parameters for getSingle operation in LogRetentionPolicyApi.
 * @export
 * @interface LogRetentionPolicyApiGetSingleRequest
 */
export type LogRetentionPolicyApiGetSingleRequest = {
    
    /**
    * Name of the Log Retention Policy
    * @type {string}
    * @memberof LogRetentionPolicyApiGetSingle
    */
    readonly logRetentionPolicyName: string
    
}

/**
 * Request parameters for listAllLogRetentionPolicies operation in LogRetentionPolicyApi.
 * @export
 * @interface LogRetentionPolicyApiListAllLogRetentionPoliciesRequest
 */
export type LogRetentionPolicyApiListAllLogRetentionPoliciesRequest = {
    
    /**
    * SCIM filter
    * @type {string}
    * @memberof LogRetentionPolicyApiListAllLogRetentionPolicies
    */
    readonly filter?: string
    
}

/**
 * Request parameters for updateByName operation in LogRetentionPolicyApi.
 * @export
 * @interface LogRetentionPolicyApiUpdateByNameRequest
 */
export type LogRetentionPolicyApiUpdateByNameRequest = {
    
    /**
    * Name of the Log Retention Policy
    * @type {string}
    * @memberof LogRetentionPolicyApiUpdateByName
    */
    readonly logRetentionPolicyName: string
    
} & UpdateRequest

/**
 * LogRetentionPolicyApiGenerated - object-oriented interface
 * @export
 * @class LogRetentionPolicyApiGenerated
 * @extends {BaseAPI}
 */
export class LogRetentionPolicyApiGenerated extends BaseAPI {
    /**
     * 
     * @summary Add a new Log Retention Policy to the config
     * @param {LogRetentionPolicyApiAddNewLogRetentionPolicyRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof LogRetentionPolicyApiGenerated
     */
    public addNewLogRetentionPolicy(requestParameters: LogRetentionPolicyApiAddNewLogRetentionPolicyRequest, options?: AxiosRequestConfig) {
        return LogRetentionPolicyApiFp(this.configuration).addNewLogRetentionPolicy(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete a Log Retention Policy
     * @param {LogRetentionPolicyApiDeleteLogRetentionPolicyRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof LogRetentionPolicyApiGenerated
     */
    public deleteLogRetentionPolicy(requestParameters: LogRetentionPolicyApiDeleteLogRetentionPolicyRequest, options?: AxiosRequestConfig) {
        return LogRetentionPolicyApiFp(this.configuration).deleteLogRetentionPolicy(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a single Log Retention Policy
     * @param {LogRetentionPolicyApiGetSingleRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof LogRetentionPolicyApiGenerated
     */
    public getSingle(requestParameters: LogRetentionPolicyApiGetSingleRequest, options?: AxiosRequestConfig) {
        return LogRetentionPolicyApiFp(this.configuration).getSingle(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a list of all Log Retention Policy objects
     * @param {LogRetentionPolicyApiListAllLogRetentionPoliciesRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof LogRetentionPolicyApiGenerated
     */
    public listAllLogRetentionPolicies(requestParameters: LogRetentionPolicyApiListAllLogRetentionPoliciesRequest = {}, options?: AxiosRequestConfig) {
        return LogRetentionPolicyApiFp(this.configuration).listAllLogRetentionPolicies(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Update an existing Log Retention Policy by name
     * @param {LogRetentionPolicyApiUpdateByNameRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof LogRetentionPolicyApiGenerated
     */
    public updateByName(requestParameters: LogRetentionPolicyApiUpdateByNameRequest, options?: AxiosRequestConfig) {
        return LogRetentionPolicyApiFp(this.configuration).updateByName(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }
}
