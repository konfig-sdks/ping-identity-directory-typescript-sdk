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
import { LdapSdkDebugLoggerResponse } from '../models';
// @ts-ignore
import { Operation } from '../models';
// @ts-ignore
import { UpdateRequest } from '../models';
import { paginate } from "../pagination/paginate";
import type * as buffer from "buffer"
import { requestBeforeHook } from '../requestBeforeHook';
/**
 * LdapSdkDebugLoggerApi - axios parameter creator
 * @export
 */
export const LdapSdkDebugLoggerApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Returns a single LDAP SDK Debug Logger
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getSingleDebugLogger: async (options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            const localVarPath = `/ldap-sdk-debug-logger`;
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
                pathTemplate: '/ldap-sdk-debug-logger',
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
         * @summary Update an existing LDAP SDK Debug Logger by name
         * @param {UpdateRequest} updateRequest Update an existing LDAP SDK Debug Logger
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName: async (updateRequest: UpdateRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'updateRequest' is not null or undefined
            assertParamExists('updateByName', 'updateRequest', updateRequest)
            const localVarPath = `/ldap-sdk-debug-logger`;
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
                pathTemplate: '/ldap-sdk-debug-logger',
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
 * LdapSdkDebugLoggerApi - functional programming interface
 * @export
 */
export const LdapSdkDebugLoggerApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = LdapSdkDebugLoggerApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Returns a single LDAP SDK Debug Logger
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async getSingleDebugLogger(options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<LdapSdkDebugLoggerResponse>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.getSingleDebugLogger(options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Update an existing LDAP SDK Debug Logger by name
         * @param {LdapSdkDebugLoggerApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async updateByName(requestParameters: LdapSdkDebugLoggerApiUpdateByNameRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<LdapSdkDebugLoggerResponse>> {
            const updateRequest: UpdateRequest = {
                operations: requestParameters.operations
            };
            const localVarAxiosArgs = await localVarAxiosParamCreator.updateByName(updateRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * LdapSdkDebugLoggerApi - factory interface
 * @export
 */
export const LdapSdkDebugLoggerApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = LdapSdkDebugLoggerApiFp(configuration)
    return {
        /**
         * 
         * @summary Returns a single LDAP SDK Debug Logger
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getSingleDebugLogger(options?: AxiosRequestConfig): AxiosPromise<LdapSdkDebugLoggerResponse> {
            return localVarFp.getSingleDebugLogger(options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Update an existing LDAP SDK Debug Logger by name
         * @param {LdapSdkDebugLoggerApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName(requestParameters: LdapSdkDebugLoggerApiUpdateByNameRequest, options?: AxiosRequestConfig): AxiosPromise<LdapSdkDebugLoggerResponse> {
            return localVarFp.updateByName(requestParameters, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * Request parameters for updateByName operation in LdapSdkDebugLoggerApi.
 * @export
 * @interface LdapSdkDebugLoggerApiUpdateByNameRequest
 */
export type LdapSdkDebugLoggerApiUpdateByNameRequest = {
    
} & UpdateRequest

/**
 * LdapSdkDebugLoggerApiGenerated - object-oriented interface
 * @export
 * @class LdapSdkDebugLoggerApiGenerated
 * @extends {BaseAPI}
 */
export class LdapSdkDebugLoggerApiGenerated extends BaseAPI {
    /**
     * 
     * @summary Returns a single LDAP SDK Debug Logger
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof LdapSdkDebugLoggerApiGenerated
     */
    public getSingleDebugLogger(options?: AxiosRequestConfig) {
        return LdapSdkDebugLoggerApiFp(this.configuration).getSingleDebugLogger(options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Update an existing LDAP SDK Debug Logger by name
     * @param {LdapSdkDebugLoggerApiUpdateByNameRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof LdapSdkDebugLoggerApiGenerated
     */
    public updateByName(requestParameters: LdapSdkDebugLoggerApiUpdateByNameRequest, options?: AxiosRequestConfig) {
        return LdapSdkDebugLoggerApiFp(this.configuration).updateByName(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }
}
