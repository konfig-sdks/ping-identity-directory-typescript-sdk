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
import { AddGenericWebApplicationExtensionRequest } from '../models';
// @ts-ignore
import { AddWebApplicationExtension200Response } from '../models';
// @ts-ignore
import { EnumgenericWebApplicationExtensionSchemaUrn } from '../models';
// @ts-ignore
import { GetWebApplicationExtension200Response } from '../models';
// @ts-ignore
import { Operation } from '../models';
// @ts-ignore
import { UpdateRequest } from '../models';
// @ts-ignore
import { WebApplicationExtensionListResponse } from '../models';
import { paginate } from "../pagination/paginate";
import type * as buffer from "buffer"
import { requestBeforeHook } from '../requestBeforeHook';
/**
 * WebApplicationExtensionApi - axios parameter creator
 * @export
 */
export const WebApplicationExtensionApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Add a new Web Application Extension to the config
         * @param {AddGenericWebApplicationExtensionRequest} addGenericWebApplicationExtensionRequest Create a new Web Application Extension in the config
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewExtension: async (addGenericWebApplicationExtensionRequest: AddGenericWebApplicationExtensionRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'addGenericWebApplicationExtensionRequest' is not null or undefined
            assertParamExists('addNewExtension', 'addGenericWebApplicationExtensionRequest', addGenericWebApplicationExtensionRequest)
            const localVarPath = `/web-application-extensions`;
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
                requestBody: addGenericWebApplicationExtensionRequest,
                queryParameters: localVarQueryParameter,
                requestConfig: localVarRequestOptions,
                path: localVarPath,
                configuration,
                pathTemplate: '/web-application-extensions',
                httpMethod: 'POST'
            });
            localVarRequestOptions.data = serializeDataIfNeeded(addGenericWebApplicationExtensionRequest, localVarRequestOptions, configuration)

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            return {
                url: toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        },
        /**
         * 
         * @summary Delete a Web Application Extension
         * @param {string} webApplicationExtensionName Name of the Web Application Extension
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deleteExtension: async (webApplicationExtensionName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'webApplicationExtensionName' is not null or undefined
            assertParamExists('deleteExtension', 'webApplicationExtensionName', webApplicationExtensionName)
            const localVarPath = `/web-application-extensions/{web-application-extension-name}`
                .replace(`{${"web-application-extension-name"}}`, encodeURIComponent(String(webApplicationExtensionName !== undefined ? webApplicationExtensionName : `-web-application-extension-name-`)));
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
                pathTemplate: '/web-application-extensions/{web-application-extension-name}',
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
         * @summary Returns a single Web Application Extension
         * @param {string} webApplicationExtensionName Name of the Web Application Extension
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getSingle: async (webApplicationExtensionName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'webApplicationExtensionName' is not null or undefined
            assertParamExists('getSingle', 'webApplicationExtensionName', webApplicationExtensionName)
            const localVarPath = `/web-application-extensions/{web-application-extension-name}`
                .replace(`{${"web-application-extension-name"}}`, encodeURIComponent(String(webApplicationExtensionName !== undefined ? webApplicationExtensionName : `-web-application-extension-name-`)));
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
                pathTemplate: '/web-application-extensions/{web-application-extension-name}',
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
         * @summary Returns a list of all Web Application Extension objects
         * @param {string} [filter] SCIM filter
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        listAllObjects: async (filter?: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            const localVarPath = `/web-application-extensions`;
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
                pathTemplate: '/web-application-extensions',
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
         * @summary Update an existing Web Application Extension by name
         * @param {string} webApplicationExtensionName Name of the Web Application Extension
         * @param {UpdateRequest} updateRequest Update an existing Web Application Extension
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName: async (webApplicationExtensionName: string, updateRequest: UpdateRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'webApplicationExtensionName' is not null or undefined
            assertParamExists('updateByName', 'webApplicationExtensionName', webApplicationExtensionName)
            // verify required parameter 'updateRequest' is not null or undefined
            assertParamExists('updateByName', 'updateRequest', updateRequest)
            const localVarPath = `/web-application-extensions/{web-application-extension-name}`
                .replace(`{${"web-application-extension-name"}}`, encodeURIComponent(String(webApplicationExtensionName !== undefined ? webApplicationExtensionName : `-web-application-extension-name-`)));
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
                pathTemplate: '/web-application-extensions/{web-application-extension-name}',
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
 * WebApplicationExtensionApi - functional programming interface
 * @export
 */
export const WebApplicationExtensionApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = WebApplicationExtensionApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Add a new Web Application Extension to the config
         * @param {WebApplicationExtensionApiAddNewExtensionRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async addNewExtension(requestParameters: WebApplicationExtensionApiAddNewExtensionRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<AddWebApplicationExtension200Response>> {
            const addGenericWebApplicationExtensionRequest: AddGenericWebApplicationExtensionRequest = {
            };
            const localVarAxiosArgs = await localVarAxiosParamCreator.addNewExtension(addGenericWebApplicationExtensionRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Delete a Web Application Extension
         * @param {WebApplicationExtensionApiDeleteExtensionRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async deleteExtension(requestParameters: WebApplicationExtensionApiDeleteExtensionRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<void>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.deleteExtension(requestParameters.webApplicationExtensionName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a single Web Application Extension
         * @param {WebApplicationExtensionApiGetSingleRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async getSingle(requestParameters: WebApplicationExtensionApiGetSingleRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<GetWebApplicationExtension200Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.getSingle(requestParameters.webApplicationExtensionName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a list of all Web Application Extension objects
         * @param {WebApplicationExtensionApiListAllObjectsRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async listAllObjects(requestParameters: WebApplicationExtensionApiListAllObjectsRequest = {}, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<WebApplicationExtensionListResponse>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.listAllObjects(requestParameters.filter, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Update an existing Web Application Extension by name
         * @param {WebApplicationExtensionApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async updateByName(requestParameters: WebApplicationExtensionApiUpdateByNameRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<GetWebApplicationExtension200Response>> {
            const updateRequest: UpdateRequest = {
                operations: requestParameters.operations
            };
            const localVarAxiosArgs = await localVarAxiosParamCreator.updateByName(requestParameters.webApplicationExtensionName, updateRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * WebApplicationExtensionApi - factory interface
 * @export
 */
export const WebApplicationExtensionApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = WebApplicationExtensionApiFp(configuration)
    return {
        /**
         * 
         * @summary Add a new Web Application Extension to the config
         * @param {WebApplicationExtensionApiAddNewExtensionRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewExtension(requestParameters: WebApplicationExtensionApiAddNewExtensionRequest, options?: AxiosRequestConfig): AxiosPromise<AddWebApplicationExtension200Response> {
            return localVarFp.addNewExtension(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete a Web Application Extension
         * @param {WebApplicationExtensionApiDeleteExtensionRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deleteExtension(requestParameters: WebApplicationExtensionApiDeleteExtensionRequest, options?: AxiosRequestConfig): AxiosPromise<void> {
            return localVarFp.deleteExtension(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a single Web Application Extension
         * @param {WebApplicationExtensionApiGetSingleRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getSingle(requestParameters: WebApplicationExtensionApiGetSingleRequest, options?: AxiosRequestConfig): AxiosPromise<GetWebApplicationExtension200Response> {
            return localVarFp.getSingle(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a list of all Web Application Extension objects
         * @param {WebApplicationExtensionApiListAllObjectsRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        listAllObjects(requestParameters: WebApplicationExtensionApiListAllObjectsRequest = {}, options?: AxiosRequestConfig): AxiosPromise<WebApplicationExtensionListResponse> {
            return localVarFp.listAllObjects(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Update an existing Web Application Extension by name
         * @param {WebApplicationExtensionApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName(requestParameters: WebApplicationExtensionApiUpdateByNameRequest, options?: AxiosRequestConfig): AxiosPromise<GetWebApplicationExtension200Response> {
            return localVarFp.updateByName(requestParameters, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * Request parameters for addNewExtension operation in WebApplicationExtensionApi.
 * @export
 * @interface WebApplicationExtensionApiAddNewExtensionRequest
 */
export type WebApplicationExtensionApiAddNewExtensionRequest = {
    
} & AddGenericWebApplicationExtensionRequest

/**
 * Request parameters for deleteExtension operation in WebApplicationExtensionApi.
 * @export
 * @interface WebApplicationExtensionApiDeleteExtensionRequest
 */
export type WebApplicationExtensionApiDeleteExtensionRequest = {
    
    /**
    * Name of the Web Application Extension
    * @type {string}
    * @memberof WebApplicationExtensionApiDeleteExtension
    */
    readonly webApplicationExtensionName: string
    
}

/**
 * Request parameters for getSingle operation in WebApplicationExtensionApi.
 * @export
 * @interface WebApplicationExtensionApiGetSingleRequest
 */
export type WebApplicationExtensionApiGetSingleRequest = {
    
    /**
    * Name of the Web Application Extension
    * @type {string}
    * @memberof WebApplicationExtensionApiGetSingle
    */
    readonly webApplicationExtensionName: string
    
}

/**
 * Request parameters for listAllObjects operation in WebApplicationExtensionApi.
 * @export
 * @interface WebApplicationExtensionApiListAllObjectsRequest
 */
export type WebApplicationExtensionApiListAllObjectsRequest = {
    
    /**
    * SCIM filter
    * @type {string}
    * @memberof WebApplicationExtensionApiListAllObjects
    */
    readonly filter?: string
    
}

/**
 * Request parameters for updateByName operation in WebApplicationExtensionApi.
 * @export
 * @interface WebApplicationExtensionApiUpdateByNameRequest
 */
export type WebApplicationExtensionApiUpdateByNameRequest = {
    
    /**
    * Name of the Web Application Extension
    * @type {string}
    * @memberof WebApplicationExtensionApiUpdateByName
    */
    readonly webApplicationExtensionName: string
    
} & UpdateRequest

/**
 * WebApplicationExtensionApiGenerated - object-oriented interface
 * @export
 * @class WebApplicationExtensionApiGenerated
 * @extends {BaseAPI}
 */
export class WebApplicationExtensionApiGenerated extends BaseAPI {
    /**
     * 
     * @summary Add a new Web Application Extension to the config
     * @param {WebApplicationExtensionApiAddNewExtensionRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof WebApplicationExtensionApiGenerated
     */
    public addNewExtension(requestParameters: WebApplicationExtensionApiAddNewExtensionRequest, options?: AxiosRequestConfig) {
        return WebApplicationExtensionApiFp(this.configuration).addNewExtension(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete a Web Application Extension
     * @param {WebApplicationExtensionApiDeleteExtensionRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof WebApplicationExtensionApiGenerated
     */
    public deleteExtension(requestParameters: WebApplicationExtensionApiDeleteExtensionRequest, options?: AxiosRequestConfig) {
        return WebApplicationExtensionApiFp(this.configuration).deleteExtension(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a single Web Application Extension
     * @param {WebApplicationExtensionApiGetSingleRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof WebApplicationExtensionApiGenerated
     */
    public getSingle(requestParameters: WebApplicationExtensionApiGetSingleRequest, options?: AxiosRequestConfig) {
        return WebApplicationExtensionApiFp(this.configuration).getSingle(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a list of all Web Application Extension objects
     * @param {WebApplicationExtensionApiListAllObjectsRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof WebApplicationExtensionApiGenerated
     */
    public listAllObjects(requestParameters: WebApplicationExtensionApiListAllObjectsRequest = {}, options?: AxiosRequestConfig) {
        return WebApplicationExtensionApiFp(this.configuration).listAllObjects(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Update an existing Web Application Extension by name
     * @param {WebApplicationExtensionApiUpdateByNameRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof WebApplicationExtensionApiGenerated
     */
    public updateByName(requestParameters: WebApplicationExtensionApiUpdateByNameRequest, options?: AxiosRequestConfig) {
        return WebApplicationExtensionApiFp(this.configuration).updateByName(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }
}
