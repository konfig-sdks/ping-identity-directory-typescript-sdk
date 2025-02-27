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
import { AddAzureAuthenticationMethod200Response } from '../models';
// @ts-ignore
import { AddAzureAuthenticationMethodRequest } from '../models';
// @ts-ignore
import { AzureAuthenticationMethodListResponse } from '../models';
// @ts-ignore
import { EnumusernamePasswordAzureAuthenticationMethodSchemaUrn } from '../models';
// @ts-ignore
import { Operation } from '../models';
// @ts-ignore
import { UpdateRequest } from '../models';
import { paginate } from "../pagination/paginate";
import type * as buffer from "buffer"
import { requestBeforeHook } from '../requestBeforeHook';
/**
 * AzureAuthenticationMethodApi - axios parameter creator
 * @export
 */
export const AzureAuthenticationMethodApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Add a new Azure Authentication Method to the config
         * @param {AddAzureAuthenticationMethodRequest} addAzureAuthenticationMethodRequest Create a new Azure Authentication Method in the config
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewConfig: async (addAzureAuthenticationMethodRequest: AddAzureAuthenticationMethodRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'addAzureAuthenticationMethodRequest' is not null or undefined
            assertParamExists('addNewConfig', 'addAzureAuthenticationMethodRequest', addAzureAuthenticationMethodRequest)
            const localVarPath = `/azure-authentication-methods`;
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
                requestBody: addAzureAuthenticationMethodRequest,
                queryParameters: localVarQueryParameter,
                requestConfig: localVarRequestOptions,
                path: localVarPath,
                configuration,
                pathTemplate: '/azure-authentication-methods',
                httpMethod: 'POST'
            });
            localVarRequestOptions.data = serializeDataIfNeeded(addAzureAuthenticationMethodRequest, localVarRequestOptions, configuration)

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            return {
                url: toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        },
        /**
         * 
         * @summary Delete a Azure Authentication Method
         * @param {string} azureAuthenticationMethodName Name of the Azure Authentication Method
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deleteAzureAuthenticationMethod: async (azureAuthenticationMethodName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'azureAuthenticationMethodName' is not null or undefined
            assertParamExists('deleteAzureAuthenticationMethod', 'azureAuthenticationMethodName', azureAuthenticationMethodName)
            const localVarPath = `/azure-authentication-methods/{azure-authentication-method-name}`
                .replace(`{${"azure-authentication-method-name"}}`, encodeURIComponent(String(azureAuthenticationMethodName !== undefined ? azureAuthenticationMethodName : `-azure-authentication-method-name-`)));
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
                pathTemplate: '/azure-authentication-methods/{azure-authentication-method-name}',
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
         * @summary Returns a list of all Azure Authentication Method objects
         * @param {string} [filter] SCIM filter
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getAllObjects: async (filter?: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            const localVarPath = `/azure-authentication-methods`;
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
                pathTemplate: '/azure-authentication-methods',
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
         * @summary Returns a single Azure Authentication Method
         * @param {string} azureAuthenticationMethodName Name of the Azure Authentication Method
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getSingleMethod: async (azureAuthenticationMethodName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'azureAuthenticationMethodName' is not null or undefined
            assertParamExists('getSingleMethod', 'azureAuthenticationMethodName', azureAuthenticationMethodName)
            const localVarPath = `/azure-authentication-methods/{azure-authentication-method-name}`
                .replace(`{${"azure-authentication-method-name"}}`, encodeURIComponent(String(azureAuthenticationMethodName !== undefined ? azureAuthenticationMethodName : `-azure-authentication-method-name-`)));
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
                pathTemplate: '/azure-authentication-methods/{azure-authentication-method-name}',
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
         * @summary Update an existing Azure Authentication Method by name
         * @param {string} azureAuthenticationMethodName Name of the Azure Authentication Method
         * @param {UpdateRequest} updateRequest Update an existing Azure Authentication Method
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName: async (azureAuthenticationMethodName: string, updateRequest: UpdateRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'azureAuthenticationMethodName' is not null or undefined
            assertParamExists('updateByName', 'azureAuthenticationMethodName', azureAuthenticationMethodName)
            // verify required parameter 'updateRequest' is not null or undefined
            assertParamExists('updateByName', 'updateRequest', updateRequest)
            const localVarPath = `/azure-authentication-methods/{azure-authentication-method-name}`
                .replace(`{${"azure-authentication-method-name"}}`, encodeURIComponent(String(azureAuthenticationMethodName !== undefined ? azureAuthenticationMethodName : `-azure-authentication-method-name-`)));
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
                pathTemplate: '/azure-authentication-methods/{azure-authentication-method-name}',
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
 * AzureAuthenticationMethodApi - functional programming interface
 * @export
 */
export const AzureAuthenticationMethodApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = AzureAuthenticationMethodApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Add a new Azure Authentication Method to the config
         * @param {AzureAuthenticationMethodApiAddNewConfigRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async addNewConfig(requestParameters: AzureAuthenticationMethodApiAddNewConfigRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<AddAzureAuthenticationMethod200Response>> {
            const addAzureAuthenticationMethodRequest: AddAzureAuthenticationMethodRequest = requestParameters;
            const localVarAxiosArgs = await localVarAxiosParamCreator.addNewConfig(addAzureAuthenticationMethodRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Delete a Azure Authentication Method
         * @param {AzureAuthenticationMethodApiDeleteAzureAuthenticationMethodRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async deleteAzureAuthenticationMethod(requestParameters: AzureAuthenticationMethodApiDeleteAzureAuthenticationMethodRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<void>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.deleteAzureAuthenticationMethod(requestParameters.azureAuthenticationMethodName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a list of all Azure Authentication Method objects
         * @param {AzureAuthenticationMethodApiGetAllObjectsRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async getAllObjects(requestParameters: AzureAuthenticationMethodApiGetAllObjectsRequest = {}, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<AzureAuthenticationMethodListResponse>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.getAllObjects(requestParameters.filter, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a single Azure Authentication Method
         * @param {AzureAuthenticationMethodApiGetSingleMethodRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async getSingleMethod(requestParameters: AzureAuthenticationMethodApiGetSingleMethodRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<AddAzureAuthenticationMethod200Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.getSingleMethod(requestParameters.azureAuthenticationMethodName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Update an existing Azure Authentication Method by name
         * @param {AzureAuthenticationMethodApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async updateByName(requestParameters: AzureAuthenticationMethodApiUpdateByNameRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<AddAzureAuthenticationMethod200Response>> {
            const updateRequest: UpdateRequest = {
                operations: requestParameters.operations
            };
            const localVarAxiosArgs = await localVarAxiosParamCreator.updateByName(requestParameters.azureAuthenticationMethodName, updateRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * AzureAuthenticationMethodApi - factory interface
 * @export
 */
export const AzureAuthenticationMethodApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = AzureAuthenticationMethodApiFp(configuration)
    return {
        /**
         * 
         * @summary Add a new Azure Authentication Method to the config
         * @param {AzureAuthenticationMethodApiAddNewConfigRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewConfig(requestParameters: AzureAuthenticationMethodApiAddNewConfigRequest, options?: AxiosRequestConfig): AxiosPromise<AddAzureAuthenticationMethod200Response> {
            return localVarFp.addNewConfig(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete a Azure Authentication Method
         * @param {AzureAuthenticationMethodApiDeleteAzureAuthenticationMethodRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deleteAzureAuthenticationMethod(requestParameters: AzureAuthenticationMethodApiDeleteAzureAuthenticationMethodRequest, options?: AxiosRequestConfig): AxiosPromise<void> {
            return localVarFp.deleteAzureAuthenticationMethod(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a list of all Azure Authentication Method objects
         * @param {AzureAuthenticationMethodApiGetAllObjectsRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getAllObjects(requestParameters: AzureAuthenticationMethodApiGetAllObjectsRequest = {}, options?: AxiosRequestConfig): AxiosPromise<AzureAuthenticationMethodListResponse> {
            return localVarFp.getAllObjects(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a single Azure Authentication Method
         * @param {AzureAuthenticationMethodApiGetSingleMethodRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getSingleMethod(requestParameters: AzureAuthenticationMethodApiGetSingleMethodRequest, options?: AxiosRequestConfig): AxiosPromise<AddAzureAuthenticationMethod200Response> {
            return localVarFp.getSingleMethod(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Update an existing Azure Authentication Method by name
         * @param {AzureAuthenticationMethodApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName(requestParameters: AzureAuthenticationMethodApiUpdateByNameRequest, options?: AxiosRequestConfig): AxiosPromise<AddAzureAuthenticationMethod200Response> {
            return localVarFp.updateByName(requestParameters, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * Request parameters for addNewConfig operation in AzureAuthenticationMethodApi.
 * @export
 * @interface AzureAuthenticationMethodApiAddNewConfigRequest
 */
export type AzureAuthenticationMethodApiAddNewConfigRequest = {
    
} & AddAzureAuthenticationMethodRequest

/**
 * Request parameters for deleteAzureAuthenticationMethod operation in AzureAuthenticationMethodApi.
 * @export
 * @interface AzureAuthenticationMethodApiDeleteAzureAuthenticationMethodRequest
 */
export type AzureAuthenticationMethodApiDeleteAzureAuthenticationMethodRequest = {
    
    /**
    * Name of the Azure Authentication Method
    * @type {string}
    * @memberof AzureAuthenticationMethodApiDeleteAzureAuthenticationMethod
    */
    readonly azureAuthenticationMethodName: string
    
}

/**
 * Request parameters for getAllObjects operation in AzureAuthenticationMethodApi.
 * @export
 * @interface AzureAuthenticationMethodApiGetAllObjectsRequest
 */
export type AzureAuthenticationMethodApiGetAllObjectsRequest = {
    
    /**
    * SCIM filter
    * @type {string}
    * @memberof AzureAuthenticationMethodApiGetAllObjects
    */
    readonly filter?: string
    
}

/**
 * Request parameters for getSingleMethod operation in AzureAuthenticationMethodApi.
 * @export
 * @interface AzureAuthenticationMethodApiGetSingleMethodRequest
 */
export type AzureAuthenticationMethodApiGetSingleMethodRequest = {
    
    /**
    * Name of the Azure Authentication Method
    * @type {string}
    * @memberof AzureAuthenticationMethodApiGetSingleMethod
    */
    readonly azureAuthenticationMethodName: string
    
}

/**
 * Request parameters for updateByName operation in AzureAuthenticationMethodApi.
 * @export
 * @interface AzureAuthenticationMethodApiUpdateByNameRequest
 */
export type AzureAuthenticationMethodApiUpdateByNameRequest = {
    
    /**
    * Name of the Azure Authentication Method
    * @type {string}
    * @memberof AzureAuthenticationMethodApiUpdateByName
    */
    readonly azureAuthenticationMethodName: string
    
} & UpdateRequest

/**
 * AzureAuthenticationMethodApiGenerated - object-oriented interface
 * @export
 * @class AzureAuthenticationMethodApiGenerated
 * @extends {BaseAPI}
 */
export class AzureAuthenticationMethodApiGenerated extends BaseAPI {
    /**
     * 
     * @summary Add a new Azure Authentication Method to the config
     * @param {AzureAuthenticationMethodApiAddNewConfigRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof AzureAuthenticationMethodApiGenerated
     */
    public addNewConfig(requestParameters: AzureAuthenticationMethodApiAddNewConfigRequest, options?: AxiosRequestConfig) {
        return AzureAuthenticationMethodApiFp(this.configuration).addNewConfig(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete a Azure Authentication Method
     * @param {AzureAuthenticationMethodApiDeleteAzureAuthenticationMethodRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof AzureAuthenticationMethodApiGenerated
     */
    public deleteAzureAuthenticationMethod(requestParameters: AzureAuthenticationMethodApiDeleteAzureAuthenticationMethodRequest, options?: AxiosRequestConfig) {
        return AzureAuthenticationMethodApiFp(this.configuration).deleteAzureAuthenticationMethod(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a list of all Azure Authentication Method objects
     * @param {AzureAuthenticationMethodApiGetAllObjectsRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof AzureAuthenticationMethodApiGenerated
     */
    public getAllObjects(requestParameters: AzureAuthenticationMethodApiGetAllObjectsRequest = {}, options?: AxiosRequestConfig) {
        return AzureAuthenticationMethodApiFp(this.configuration).getAllObjects(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a single Azure Authentication Method
     * @param {AzureAuthenticationMethodApiGetSingleMethodRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof AzureAuthenticationMethodApiGenerated
     */
    public getSingleMethod(requestParameters: AzureAuthenticationMethodApiGetSingleMethodRequest, options?: AxiosRequestConfig) {
        return AzureAuthenticationMethodApiFp(this.configuration).getSingleMethod(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Update an existing Azure Authentication Method by name
     * @param {AzureAuthenticationMethodApiUpdateByNameRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof AzureAuthenticationMethodApiGenerated
     */
    public updateByName(requestParameters: AzureAuthenticationMethodApiUpdateByNameRequest, options?: AxiosRequestConfig) {
        return AzureAuthenticationMethodApiFp(this.configuration).updateByName(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }
}
