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
import { AddCertificateMapper200Response } from '../models';
// @ts-ignore
import { AddCertificateMapperRequest } from '../models';
// @ts-ignore
import { CertificateMapperListResponse } from '../models';
// @ts-ignore
import { EnumcertificateMapperFingerprintAlgorithmProp } from '../models';
// @ts-ignore
import { EnumthirdPartyCertificateMapperSchemaUrn } from '../models';
// @ts-ignore
import { Operation } from '../models';
// @ts-ignore
import { UpdateRequest } from '../models';
import { paginate } from "../pagination/paginate";
import type * as buffer from "buffer"
import { requestBeforeHook } from '../requestBeforeHook';
/**
 * CertificateMapperApi - axios parameter creator
 * @export
 */
export const CertificateMapperApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Add a new Certificate Mapper to the config
         * @param {AddCertificateMapperRequest} addCertificateMapperRequest Create a new Certificate Mapper in the config
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewMapper: async (addCertificateMapperRequest: AddCertificateMapperRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'addCertificateMapperRequest' is not null or undefined
            assertParamExists('addNewMapper', 'addCertificateMapperRequest', addCertificateMapperRequest)
            const localVarPath = `/certificate-mappers`;
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
                requestBody: addCertificateMapperRequest,
                queryParameters: localVarQueryParameter,
                requestConfig: localVarRequestOptions,
                path: localVarPath,
                configuration,
                pathTemplate: '/certificate-mappers',
                httpMethod: 'POST'
            });
            localVarRequestOptions.data = serializeDataIfNeeded(addCertificateMapperRequest, localVarRequestOptions, configuration)

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            return {
                url: toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        },
        /**
         * 
         * @summary Delete a Certificate Mapper
         * @param {string} certificateMapperName Name of the Certificate Mapper
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deleteMapper: async (certificateMapperName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'certificateMapperName' is not null or undefined
            assertParamExists('deleteMapper', 'certificateMapperName', certificateMapperName)
            const localVarPath = `/certificate-mappers/{certificate-mapper-name}`
                .replace(`{${"certificate-mapper-name"}}`, encodeURIComponent(String(certificateMapperName !== undefined ? certificateMapperName : `-certificate-mapper-name-`)));
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
                pathTemplate: '/certificate-mappers/{certificate-mapper-name}',
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
         * @summary Returns a single Certificate Mapper
         * @param {string} certificateMapperName Name of the Certificate Mapper
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getSingle: async (certificateMapperName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'certificateMapperName' is not null or undefined
            assertParamExists('getSingle', 'certificateMapperName', certificateMapperName)
            const localVarPath = `/certificate-mappers/{certificate-mapper-name}`
                .replace(`{${"certificate-mapper-name"}}`, encodeURIComponent(String(certificateMapperName !== undefined ? certificateMapperName : `-certificate-mapper-name-`)));
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
                pathTemplate: '/certificate-mappers/{certificate-mapper-name}',
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
         * @summary Returns a list of all Certificate Mapper objects
         * @param {string} [filter] SCIM filter
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        listAllObjects: async (filter?: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            const localVarPath = `/certificate-mappers`;
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
                pathTemplate: '/certificate-mappers',
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
         * @summary Update an existing Certificate Mapper by name
         * @param {string} certificateMapperName Name of the Certificate Mapper
         * @param {UpdateRequest} updateRequest Update an existing Certificate Mapper
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName: async (certificateMapperName: string, updateRequest: UpdateRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'certificateMapperName' is not null or undefined
            assertParamExists('updateByName', 'certificateMapperName', certificateMapperName)
            // verify required parameter 'updateRequest' is not null or undefined
            assertParamExists('updateByName', 'updateRequest', updateRequest)
            const localVarPath = `/certificate-mappers/{certificate-mapper-name}`
                .replace(`{${"certificate-mapper-name"}}`, encodeURIComponent(String(certificateMapperName !== undefined ? certificateMapperName : `-certificate-mapper-name-`)));
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
                pathTemplate: '/certificate-mappers/{certificate-mapper-name}',
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
 * CertificateMapperApi - functional programming interface
 * @export
 */
export const CertificateMapperApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = CertificateMapperApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Add a new Certificate Mapper to the config
         * @param {CertificateMapperApiAddNewMapperRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async addNewMapper(requestParameters: CertificateMapperApiAddNewMapperRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<AddCertificateMapper200Response>> {
            const addCertificateMapperRequest: AddCertificateMapperRequest = requestParameters;
            const localVarAxiosArgs = await localVarAxiosParamCreator.addNewMapper(addCertificateMapperRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Delete a Certificate Mapper
         * @param {CertificateMapperApiDeleteMapperRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async deleteMapper(requestParameters: CertificateMapperApiDeleteMapperRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<void>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.deleteMapper(requestParameters.certificateMapperName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a single Certificate Mapper
         * @param {CertificateMapperApiGetSingleRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async getSingle(requestParameters: CertificateMapperApiGetSingleRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<AddCertificateMapper200Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.getSingle(requestParameters.certificateMapperName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a list of all Certificate Mapper objects
         * @param {CertificateMapperApiListAllObjectsRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async listAllObjects(requestParameters: CertificateMapperApiListAllObjectsRequest = {}, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<CertificateMapperListResponse>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.listAllObjects(requestParameters.filter, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Update an existing Certificate Mapper by name
         * @param {CertificateMapperApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async updateByName(requestParameters: CertificateMapperApiUpdateByNameRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<AddCertificateMapper200Response>> {
            const updateRequest: UpdateRequest = {
                operations: requestParameters.operations
            };
            const localVarAxiosArgs = await localVarAxiosParamCreator.updateByName(requestParameters.certificateMapperName, updateRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * CertificateMapperApi - factory interface
 * @export
 */
export const CertificateMapperApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = CertificateMapperApiFp(configuration)
    return {
        /**
         * 
         * @summary Add a new Certificate Mapper to the config
         * @param {CertificateMapperApiAddNewMapperRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewMapper(requestParameters: CertificateMapperApiAddNewMapperRequest, options?: AxiosRequestConfig): AxiosPromise<AddCertificateMapper200Response> {
            return localVarFp.addNewMapper(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete a Certificate Mapper
         * @param {CertificateMapperApiDeleteMapperRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deleteMapper(requestParameters: CertificateMapperApiDeleteMapperRequest, options?: AxiosRequestConfig): AxiosPromise<void> {
            return localVarFp.deleteMapper(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a single Certificate Mapper
         * @param {CertificateMapperApiGetSingleRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getSingle(requestParameters: CertificateMapperApiGetSingleRequest, options?: AxiosRequestConfig): AxiosPromise<AddCertificateMapper200Response> {
            return localVarFp.getSingle(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a list of all Certificate Mapper objects
         * @param {CertificateMapperApiListAllObjectsRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        listAllObjects(requestParameters: CertificateMapperApiListAllObjectsRequest = {}, options?: AxiosRequestConfig): AxiosPromise<CertificateMapperListResponse> {
            return localVarFp.listAllObjects(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Update an existing Certificate Mapper by name
         * @param {CertificateMapperApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName(requestParameters: CertificateMapperApiUpdateByNameRequest, options?: AxiosRequestConfig): AxiosPromise<AddCertificateMapper200Response> {
            return localVarFp.updateByName(requestParameters, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * Request parameters for addNewMapper operation in CertificateMapperApi.
 * @export
 * @interface CertificateMapperApiAddNewMapperRequest
 */
export type CertificateMapperApiAddNewMapperRequest = {
    
} & AddCertificateMapperRequest

/**
 * Request parameters for deleteMapper operation in CertificateMapperApi.
 * @export
 * @interface CertificateMapperApiDeleteMapperRequest
 */
export type CertificateMapperApiDeleteMapperRequest = {
    
    /**
    * Name of the Certificate Mapper
    * @type {string}
    * @memberof CertificateMapperApiDeleteMapper
    */
    readonly certificateMapperName: string
    
}

/**
 * Request parameters for getSingle operation in CertificateMapperApi.
 * @export
 * @interface CertificateMapperApiGetSingleRequest
 */
export type CertificateMapperApiGetSingleRequest = {
    
    /**
    * Name of the Certificate Mapper
    * @type {string}
    * @memberof CertificateMapperApiGetSingle
    */
    readonly certificateMapperName: string
    
}

/**
 * Request parameters for listAllObjects operation in CertificateMapperApi.
 * @export
 * @interface CertificateMapperApiListAllObjectsRequest
 */
export type CertificateMapperApiListAllObjectsRequest = {
    
    /**
    * SCIM filter
    * @type {string}
    * @memberof CertificateMapperApiListAllObjects
    */
    readonly filter?: string
    
}

/**
 * Request parameters for updateByName operation in CertificateMapperApi.
 * @export
 * @interface CertificateMapperApiUpdateByNameRequest
 */
export type CertificateMapperApiUpdateByNameRequest = {
    
    /**
    * Name of the Certificate Mapper
    * @type {string}
    * @memberof CertificateMapperApiUpdateByName
    */
    readonly certificateMapperName: string
    
} & UpdateRequest

/**
 * CertificateMapperApiGenerated - object-oriented interface
 * @export
 * @class CertificateMapperApiGenerated
 * @extends {BaseAPI}
 */
export class CertificateMapperApiGenerated extends BaseAPI {
    /**
     * 
     * @summary Add a new Certificate Mapper to the config
     * @param {CertificateMapperApiAddNewMapperRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof CertificateMapperApiGenerated
     */
    public addNewMapper(requestParameters: CertificateMapperApiAddNewMapperRequest, options?: AxiosRequestConfig) {
        return CertificateMapperApiFp(this.configuration).addNewMapper(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete a Certificate Mapper
     * @param {CertificateMapperApiDeleteMapperRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof CertificateMapperApiGenerated
     */
    public deleteMapper(requestParameters: CertificateMapperApiDeleteMapperRequest, options?: AxiosRequestConfig) {
        return CertificateMapperApiFp(this.configuration).deleteMapper(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a single Certificate Mapper
     * @param {CertificateMapperApiGetSingleRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof CertificateMapperApiGenerated
     */
    public getSingle(requestParameters: CertificateMapperApiGetSingleRequest, options?: AxiosRequestConfig) {
        return CertificateMapperApiFp(this.configuration).getSingle(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a list of all Certificate Mapper objects
     * @param {CertificateMapperApiListAllObjectsRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof CertificateMapperApiGenerated
     */
    public listAllObjects(requestParameters: CertificateMapperApiListAllObjectsRequest = {}, options?: AxiosRequestConfig) {
        return CertificateMapperApiFp(this.configuration).listAllObjects(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Update an existing Certificate Mapper by name
     * @param {CertificateMapperApiUpdateByNameRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof CertificateMapperApiGenerated
     */
    public updateByName(requestParameters: CertificateMapperApiUpdateByNameRequest, options?: AxiosRequestConfig) {
        return CertificateMapperApiFp(this.configuration).updateByName(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }
}
