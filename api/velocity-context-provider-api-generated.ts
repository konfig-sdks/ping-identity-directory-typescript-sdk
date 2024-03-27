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
import { AddVelocityContextProvider200Response } from '../models';
// @ts-ignore
import { AddVelocityContextProviderRequest } from '../models';
// @ts-ignore
import { EnumthirdPartyVelocityContextProviderSchemaUrn } from '../models';
// @ts-ignore
import { EnumvelocityContextProviderObjectScopeProp } from '../models';
// @ts-ignore
import { GetVelocityContextProvider200Response } from '../models';
// @ts-ignore
import { Operation } from '../models';
// @ts-ignore
import { UpdateRequest } from '../models';
// @ts-ignore
import { VelocityContextProviderListResponse } from '../models';
import { paginate } from "../pagination/paginate";
import type * as buffer from "buffer"
import { requestBeforeHook } from '../requestBeforeHook';
/**
 * VelocityContextProviderApi - axios parameter creator
 * @export
 */
export const VelocityContextProviderApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Add a new Velocity Context Provider to the config
         * @param {string} httpServletExtensionName Name of the HTTP Servlet Extension
         * @param {AddVelocityContextProviderRequest} addVelocityContextProviderRequest Create a new Velocity Context Provider in the config
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewProviderToConfig: async (httpServletExtensionName: string, addVelocityContextProviderRequest: AddVelocityContextProviderRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'httpServletExtensionName' is not null or undefined
            assertParamExists('addNewProviderToConfig', 'httpServletExtensionName', httpServletExtensionName)
            // verify required parameter 'addVelocityContextProviderRequest' is not null or undefined
            assertParamExists('addNewProviderToConfig', 'addVelocityContextProviderRequest', addVelocityContextProviderRequest)
            const localVarPath = `/http-servlet-extensions/{http-servlet-extension-name}/velocity-context-providers`
                .replace(`{${"http-servlet-extension-name"}}`, encodeURIComponent(String(httpServletExtensionName !== undefined ? httpServletExtensionName : `-http-servlet-extension-name-`)));
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
                requestBody: addVelocityContextProviderRequest,
                queryParameters: localVarQueryParameter,
                requestConfig: localVarRequestOptions,
                path: localVarPath,
                configuration,
                pathTemplate: '/http-servlet-extensions/{http-servlet-extension-name}/velocity-context-providers',
                httpMethod: 'POST'
            });
            localVarRequestOptions.data = serializeDataIfNeeded(addVelocityContextProviderRequest, localVarRequestOptions, configuration)

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            return {
                url: toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        },
        /**
         * 
         * @summary Delete a Velocity Context Provider
         * @param {string} velocityContextProviderName Name of the Velocity Context Provider
         * @param {string} httpServletExtensionName Name of the HTTP Servlet Extension
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deleteVelocityContextProvider: async (velocityContextProviderName: string, httpServletExtensionName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'velocityContextProviderName' is not null or undefined
            assertParamExists('deleteVelocityContextProvider', 'velocityContextProviderName', velocityContextProviderName)
            // verify required parameter 'httpServletExtensionName' is not null or undefined
            assertParamExists('deleteVelocityContextProvider', 'httpServletExtensionName', httpServletExtensionName)
            const localVarPath = `/http-servlet-extensions/{http-servlet-extension-name}/velocity-context-providers/{velocity-context-provider-name}`
                .replace(`{${"velocity-context-provider-name"}}`, encodeURIComponent(String(velocityContextProviderName !== undefined ? velocityContextProviderName : `-velocity-context-provider-name-`)))
                .replace(`{${"http-servlet-extension-name"}}`, encodeURIComponent(String(httpServletExtensionName !== undefined ? httpServletExtensionName : `-http-servlet-extension-name-`)));
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
                pathTemplate: '/http-servlet-extensions/{http-servlet-extension-name}/velocity-context-providers/{velocity-context-provider-name}',
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
         * @summary Returns a single Velocity Context Provider
         * @param {string} velocityContextProviderName Name of the Velocity Context Provider
         * @param {string} httpServletExtensionName Name of the HTTP Servlet Extension
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getSingleVelocityContextProvider: async (velocityContextProviderName: string, httpServletExtensionName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'velocityContextProviderName' is not null or undefined
            assertParamExists('getSingleVelocityContextProvider', 'velocityContextProviderName', velocityContextProviderName)
            // verify required parameter 'httpServletExtensionName' is not null or undefined
            assertParamExists('getSingleVelocityContextProvider', 'httpServletExtensionName', httpServletExtensionName)
            const localVarPath = `/http-servlet-extensions/{http-servlet-extension-name}/velocity-context-providers/{velocity-context-provider-name}`
                .replace(`{${"velocity-context-provider-name"}}`, encodeURIComponent(String(velocityContextProviderName !== undefined ? velocityContextProviderName : `-velocity-context-provider-name-`)))
                .replace(`{${"http-servlet-extension-name"}}`, encodeURIComponent(String(httpServletExtensionName !== undefined ? httpServletExtensionName : `-http-servlet-extension-name-`)));
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
                pathTemplate: '/http-servlet-extensions/{http-servlet-extension-name}/velocity-context-providers/{velocity-context-provider-name}',
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
         * @summary Returns a list of all Velocity Context Provider objects
         * @param {string} httpServletExtensionName Name of the HTTP Servlet Extension
         * @param {string} [filter] SCIM filter
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        listAllVelocityContextProviders: async (httpServletExtensionName: string, filter?: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'httpServletExtensionName' is not null or undefined
            assertParamExists('listAllVelocityContextProviders', 'httpServletExtensionName', httpServletExtensionName)
            const localVarPath = `/http-servlet-extensions/{http-servlet-extension-name}/velocity-context-providers`
                .replace(`{${"http-servlet-extension-name"}}`, encodeURIComponent(String(httpServletExtensionName !== undefined ? httpServletExtensionName : `-http-servlet-extension-name-`)));
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
                pathTemplate: '/http-servlet-extensions/{http-servlet-extension-name}/velocity-context-providers',
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
         * @summary Update an existing Velocity Context Provider by name
         * @param {string} velocityContextProviderName Name of the Velocity Context Provider
         * @param {string} httpServletExtensionName Name of the HTTP Servlet Extension
         * @param {UpdateRequest} updateRequest Update an existing Velocity Context Provider
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateBynameVelocityContextProvider: async (velocityContextProviderName: string, httpServletExtensionName: string, updateRequest: UpdateRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'velocityContextProviderName' is not null or undefined
            assertParamExists('updateBynameVelocityContextProvider', 'velocityContextProviderName', velocityContextProviderName)
            // verify required parameter 'httpServletExtensionName' is not null or undefined
            assertParamExists('updateBynameVelocityContextProvider', 'httpServletExtensionName', httpServletExtensionName)
            // verify required parameter 'updateRequest' is not null or undefined
            assertParamExists('updateBynameVelocityContextProvider', 'updateRequest', updateRequest)
            const localVarPath = `/http-servlet-extensions/{http-servlet-extension-name}/velocity-context-providers/{velocity-context-provider-name}`
                .replace(`{${"velocity-context-provider-name"}}`, encodeURIComponent(String(velocityContextProviderName !== undefined ? velocityContextProviderName : `-velocity-context-provider-name-`)))
                .replace(`{${"http-servlet-extension-name"}}`, encodeURIComponent(String(httpServletExtensionName !== undefined ? httpServletExtensionName : `-http-servlet-extension-name-`)));
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
                pathTemplate: '/http-servlet-extensions/{http-servlet-extension-name}/velocity-context-providers/{velocity-context-provider-name}',
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
 * VelocityContextProviderApi - functional programming interface
 * @export
 */
export const VelocityContextProviderApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = VelocityContextProviderApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Add a new Velocity Context Provider to the config
         * @param {VelocityContextProviderApiAddNewProviderToConfigRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async addNewProviderToConfig(requestParameters: VelocityContextProviderApiAddNewProviderToConfigRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<AddVelocityContextProvider200Response>> {
            const addVelocityContextProviderRequest: AddVelocityContextProviderRequest = requestParameters;
            const localVarAxiosArgs = await localVarAxiosParamCreator.addNewProviderToConfig(requestParameters.httpServletExtensionName, addVelocityContextProviderRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Delete a Velocity Context Provider
         * @param {VelocityContextProviderApiDeleteVelocityContextProviderRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async deleteVelocityContextProvider(requestParameters: VelocityContextProviderApiDeleteVelocityContextProviderRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<void>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.deleteVelocityContextProvider(requestParameters.velocityContextProviderName, requestParameters.httpServletExtensionName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a single Velocity Context Provider
         * @param {VelocityContextProviderApiGetSingleVelocityContextProviderRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async getSingleVelocityContextProvider(requestParameters: VelocityContextProviderApiGetSingleVelocityContextProviderRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<GetVelocityContextProvider200Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.getSingleVelocityContextProvider(requestParameters.velocityContextProviderName, requestParameters.httpServletExtensionName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a list of all Velocity Context Provider objects
         * @param {VelocityContextProviderApiListAllVelocityContextProvidersRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async listAllVelocityContextProviders(requestParameters: VelocityContextProviderApiListAllVelocityContextProvidersRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<VelocityContextProviderListResponse>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.listAllVelocityContextProviders(requestParameters.httpServletExtensionName, requestParameters.filter, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Update an existing Velocity Context Provider by name
         * @param {VelocityContextProviderApiUpdateBynameVelocityContextProviderRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async updateBynameVelocityContextProvider(requestParameters: VelocityContextProviderApiUpdateBynameVelocityContextProviderRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<GetVelocityContextProvider200Response>> {
            const updateRequest: UpdateRequest = {
                operations: requestParameters.operations
            };
            const localVarAxiosArgs = await localVarAxiosParamCreator.updateBynameVelocityContextProvider(requestParameters.velocityContextProviderName, requestParameters.httpServletExtensionName, updateRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * VelocityContextProviderApi - factory interface
 * @export
 */
export const VelocityContextProviderApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = VelocityContextProviderApiFp(configuration)
    return {
        /**
         * 
         * @summary Add a new Velocity Context Provider to the config
         * @param {VelocityContextProviderApiAddNewProviderToConfigRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewProviderToConfig(requestParameters: VelocityContextProviderApiAddNewProviderToConfigRequest, options?: AxiosRequestConfig): AxiosPromise<AddVelocityContextProvider200Response> {
            return localVarFp.addNewProviderToConfig(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete a Velocity Context Provider
         * @param {VelocityContextProviderApiDeleteVelocityContextProviderRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deleteVelocityContextProvider(requestParameters: VelocityContextProviderApiDeleteVelocityContextProviderRequest, options?: AxiosRequestConfig): AxiosPromise<void> {
            return localVarFp.deleteVelocityContextProvider(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a single Velocity Context Provider
         * @param {VelocityContextProviderApiGetSingleVelocityContextProviderRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getSingleVelocityContextProvider(requestParameters: VelocityContextProviderApiGetSingleVelocityContextProviderRequest, options?: AxiosRequestConfig): AxiosPromise<GetVelocityContextProvider200Response> {
            return localVarFp.getSingleVelocityContextProvider(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a list of all Velocity Context Provider objects
         * @param {VelocityContextProviderApiListAllVelocityContextProvidersRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        listAllVelocityContextProviders(requestParameters: VelocityContextProviderApiListAllVelocityContextProvidersRequest, options?: AxiosRequestConfig): AxiosPromise<VelocityContextProviderListResponse> {
            return localVarFp.listAllVelocityContextProviders(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Update an existing Velocity Context Provider by name
         * @param {VelocityContextProviderApiUpdateBynameVelocityContextProviderRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateBynameVelocityContextProvider(requestParameters: VelocityContextProviderApiUpdateBynameVelocityContextProviderRequest, options?: AxiosRequestConfig): AxiosPromise<GetVelocityContextProvider200Response> {
            return localVarFp.updateBynameVelocityContextProvider(requestParameters, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * Request parameters for addNewProviderToConfig operation in VelocityContextProviderApi.
 * @export
 * @interface VelocityContextProviderApiAddNewProviderToConfigRequest
 */
export type VelocityContextProviderApiAddNewProviderToConfigRequest = {
    
    /**
    * Name of the HTTP Servlet Extension
    * @type {string}
    * @memberof VelocityContextProviderApiAddNewProviderToConfig
    */
    readonly httpServletExtensionName: string
    
} & AddVelocityContextProviderRequest

/**
 * Request parameters for deleteVelocityContextProvider operation in VelocityContextProviderApi.
 * @export
 * @interface VelocityContextProviderApiDeleteVelocityContextProviderRequest
 */
export type VelocityContextProviderApiDeleteVelocityContextProviderRequest = {
    
    /**
    * Name of the Velocity Context Provider
    * @type {string}
    * @memberof VelocityContextProviderApiDeleteVelocityContextProvider
    */
    readonly velocityContextProviderName: string
    
    /**
    * Name of the HTTP Servlet Extension
    * @type {string}
    * @memberof VelocityContextProviderApiDeleteVelocityContextProvider
    */
    readonly httpServletExtensionName: string
    
}

/**
 * Request parameters for getSingleVelocityContextProvider operation in VelocityContextProviderApi.
 * @export
 * @interface VelocityContextProviderApiGetSingleVelocityContextProviderRequest
 */
export type VelocityContextProviderApiGetSingleVelocityContextProviderRequest = {
    
    /**
    * Name of the Velocity Context Provider
    * @type {string}
    * @memberof VelocityContextProviderApiGetSingleVelocityContextProvider
    */
    readonly velocityContextProviderName: string
    
    /**
    * Name of the HTTP Servlet Extension
    * @type {string}
    * @memberof VelocityContextProviderApiGetSingleVelocityContextProvider
    */
    readonly httpServletExtensionName: string
    
}

/**
 * Request parameters for listAllVelocityContextProviders operation in VelocityContextProviderApi.
 * @export
 * @interface VelocityContextProviderApiListAllVelocityContextProvidersRequest
 */
export type VelocityContextProviderApiListAllVelocityContextProvidersRequest = {
    
    /**
    * Name of the HTTP Servlet Extension
    * @type {string}
    * @memberof VelocityContextProviderApiListAllVelocityContextProviders
    */
    readonly httpServletExtensionName: string
    
    /**
    * SCIM filter
    * @type {string}
    * @memberof VelocityContextProviderApiListAllVelocityContextProviders
    */
    readonly filter?: string
    
}

/**
 * Request parameters for updateBynameVelocityContextProvider operation in VelocityContextProviderApi.
 * @export
 * @interface VelocityContextProviderApiUpdateBynameVelocityContextProviderRequest
 */
export type VelocityContextProviderApiUpdateBynameVelocityContextProviderRequest = {
    
    /**
    * Name of the Velocity Context Provider
    * @type {string}
    * @memberof VelocityContextProviderApiUpdateBynameVelocityContextProvider
    */
    readonly velocityContextProviderName: string
    
    /**
    * Name of the HTTP Servlet Extension
    * @type {string}
    * @memberof VelocityContextProviderApiUpdateBynameVelocityContextProvider
    */
    readonly httpServletExtensionName: string
    
} & UpdateRequest

/**
 * VelocityContextProviderApiGenerated - object-oriented interface
 * @export
 * @class VelocityContextProviderApiGenerated
 * @extends {BaseAPI}
 */
export class VelocityContextProviderApiGenerated extends BaseAPI {
    /**
     * 
     * @summary Add a new Velocity Context Provider to the config
     * @param {VelocityContextProviderApiAddNewProviderToConfigRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof VelocityContextProviderApiGenerated
     */
    public addNewProviderToConfig(requestParameters: VelocityContextProviderApiAddNewProviderToConfigRequest, options?: AxiosRequestConfig) {
        return VelocityContextProviderApiFp(this.configuration).addNewProviderToConfig(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete a Velocity Context Provider
     * @param {VelocityContextProviderApiDeleteVelocityContextProviderRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof VelocityContextProviderApiGenerated
     */
    public deleteVelocityContextProvider(requestParameters: VelocityContextProviderApiDeleteVelocityContextProviderRequest, options?: AxiosRequestConfig) {
        return VelocityContextProviderApiFp(this.configuration).deleteVelocityContextProvider(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a single Velocity Context Provider
     * @param {VelocityContextProviderApiGetSingleVelocityContextProviderRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof VelocityContextProviderApiGenerated
     */
    public getSingleVelocityContextProvider(requestParameters: VelocityContextProviderApiGetSingleVelocityContextProviderRequest, options?: AxiosRequestConfig) {
        return VelocityContextProviderApiFp(this.configuration).getSingleVelocityContextProvider(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a list of all Velocity Context Provider objects
     * @param {VelocityContextProviderApiListAllVelocityContextProvidersRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof VelocityContextProviderApiGenerated
     */
    public listAllVelocityContextProviders(requestParameters: VelocityContextProviderApiListAllVelocityContextProvidersRequest, options?: AxiosRequestConfig) {
        return VelocityContextProviderApiFp(this.configuration).listAllVelocityContextProviders(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Update an existing Velocity Context Provider by name
     * @param {VelocityContextProviderApiUpdateBynameVelocityContextProviderRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof VelocityContextProviderApiGenerated
     */
    public updateBynameVelocityContextProvider(requestParameters: VelocityContextProviderApiUpdateBynameVelocityContextProviderRequest, options?: AxiosRequestConfig) {
        return VelocityContextProviderApiFp(this.configuration).updateBynameVelocityContextProvider(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }
}
