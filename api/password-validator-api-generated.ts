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
import { AddPasswordValidator200Response } from '../models';
// @ts-ignore
import { AddPasswordValidatorRequest } from '../models';
// @ts-ignore
import { EnumpasswordValidatorAllowedCharacterTypeProp } from '../models';
// @ts-ignore
import { EnumpasswordValidatorMatchBehaviorProp } from '../models';
// @ts-ignore
import { EnumthirdPartyPasswordValidatorSchemaUrn } from '../models';
// @ts-ignore
import { GetPasswordValidator200Response } from '../models';
// @ts-ignore
import { Operation } from '../models';
// @ts-ignore
import { PasswordValidatorListResponse } from '../models';
// @ts-ignore
import { UpdateRequest } from '../models';
import { paginate } from "../pagination/paginate";
import type * as buffer from "buffer"
import { requestBeforeHook } from '../requestBeforeHook';
/**
 * PasswordValidatorApi - axios parameter creator
 * @export
 */
export const PasswordValidatorApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Add a new Password Validator to the config
         * @param {AddPasswordValidatorRequest} addPasswordValidatorRequest Create a new Password Validator in the config
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewValidatorToConfig: async (addPasswordValidatorRequest: AddPasswordValidatorRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'addPasswordValidatorRequest' is not null or undefined
            assertParamExists('addNewValidatorToConfig', 'addPasswordValidatorRequest', addPasswordValidatorRequest)
            const localVarPath = `/password-validators`;
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
                requestBody: addPasswordValidatorRequest,
                queryParameters: localVarQueryParameter,
                requestConfig: localVarRequestOptions,
                path: localVarPath,
                configuration,
                pathTemplate: '/password-validators',
                httpMethod: 'POST'
            });
            localVarRequestOptions.data = serializeDataIfNeeded(addPasswordValidatorRequest, localVarRequestOptions, configuration)

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            return {
                url: toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        },
        /**
         * 
         * @summary Delete a Password Validator
         * @param {string} passwordValidatorName Name of the Password Validator
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deleteValidator: async (passwordValidatorName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'passwordValidatorName' is not null or undefined
            assertParamExists('deleteValidator', 'passwordValidatorName', passwordValidatorName)
            const localVarPath = `/password-validators/{password-validator-name}`
                .replace(`{${"password-validator-name"}}`, encodeURIComponent(String(passwordValidatorName !== undefined ? passwordValidatorName : `-password-validator-name-`)));
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
                pathTemplate: '/password-validators/{password-validator-name}',
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
         * @summary Returns a list of all Password Validator objects
         * @param {string} [filter] SCIM filter
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getAllValidators: async (filter?: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            const localVarPath = `/password-validators`;
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
                pathTemplate: '/password-validators',
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
         * @summary Returns a single Password Validator
         * @param {string} passwordValidatorName Name of the Password Validator
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getValidator: async (passwordValidatorName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'passwordValidatorName' is not null or undefined
            assertParamExists('getValidator', 'passwordValidatorName', passwordValidatorName)
            const localVarPath = `/password-validators/{password-validator-name}`
                .replace(`{${"password-validator-name"}}`, encodeURIComponent(String(passwordValidatorName !== undefined ? passwordValidatorName : `-password-validator-name-`)));
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
                pathTemplate: '/password-validators/{password-validator-name}',
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
         * @summary Update an existing Password Validator by name
         * @param {string} passwordValidatorName Name of the Password Validator
         * @param {UpdateRequest} updateRequest Update an existing Password Validator
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName: async (passwordValidatorName: string, updateRequest: UpdateRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'passwordValidatorName' is not null or undefined
            assertParamExists('updateByName', 'passwordValidatorName', passwordValidatorName)
            // verify required parameter 'updateRequest' is not null or undefined
            assertParamExists('updateByName', 'updateRequest', updateRequest)
            const localVarPath = `/password-validators/{password-validator-name}`
                .replace(`{${"password-validator-name"}}`, encodeURIComponent(String(passwordValidatorName !== undefined ? passwordValidatorName : `-password-validator-name-`)));
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
                pathTemplate: '/password-validators/{password-validator-name}',
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
 * PasswordValidatorApi - functional programming interface
 * @export
 */
export const PasswordValidatorApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = PasswordValidatorApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Add a new Password Validator to the config
         * @param {PasswordValidatorApiAddNewValidatorToConfigRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async addNewValidatorToConfig(requestParameters: PasswordValidatorApiAddNewValidatorToConfigRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<AddPasswordValidator200Response>> {
            const addPasswordValidatorRequest: AddPasswordValidatorRequest = requestParameters;
            const localVarAxiosArgs = await localVarAxiosParamCreator.addNewValidatorToConfig(addPasswordValidatorRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Delete a Password Validator
         * @param {PasswordValidatorApiDeleteValidatorRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async deleteValidator(requestParameters: PasswordValidatorApiDeleteValidatorRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<void>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.deleteValidator(requestParameters.passwordValidatorName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a list of all Password Validator objects
         * @param {PasswordValidatorApiGetAllValidatorsRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async getAllValidators(requestParameters: PasswordValidatorApiGetAllValidatorsRequest = {}, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<PasswordValidatorListResponse>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.getAllValidators(requestParameters.filter, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a single Password Validator
         * @param {PasswordValidatorApiGetValidatorRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async getValidator(requestParameters: PasswordValidatorApiGetValidatorRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<GetPasswordValidator200Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.getValidator(requestParameters.passwordValidatorName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Update an existing Password Validator by name
         * @param {PasswordValidatorApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async updateByName(requestParameters: PasswordValidatorApiUpdateByNameRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<GetPasswordValidator200Response>> {
            const updateRequest: UpdateRequest = {
                operations: requestParameters.operations
            };
            const localVarAxiosArgs = await localVarAxiosParamCreator.updateByName(requestParameters.passwordValidatorName, updateRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * PasswordValidatorApi - factory interface
 * @export
 */
export const PasswordValidatorApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = PasswordValidatorApiFp(configuration)
    return {
        /**
         * 
         * @summary Add a new Password Validator to the config
         * @param {PasswordValidatorApiAddNewValidatorToConfigRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewValidatorToConfig(requestParameters: PasswordValidatorApiAddNewValidatorToConfigRequest, options?: AxiosRequestConfig): AxiosPromise<AddPasswordValidator200Response> {
            return localVarFp.addNewValidatorToConfig(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete a Password Validator
         * @param {PasswordValidatorApiDeleteValidatorRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deleteValidator(requestParameters: PasswordValidatorApiDeleteValidatorRequest, options?: AxiosRequestConfig): AxiosPromise<void> {
            return localVarFp.deleteValidator(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a list of all Password Validator objects
         * @param {PasswordValidatorApiGetAllValidatorsRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getAllValidators(requestParameters: PasswordValidatorApiGetAllValidatorsRequest = {}, options?: AxiosRequestConfig): AxiosPromise<PasswordValidatorListResponse> {
            return localVarFp.getAllValidators(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a single Password Validator
         * @param {PasswordValidatorApiGetValidatorRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getValidator(requestParameters: PasswordValidatorApiGetValidatorRequest, options?: AxiosRequestConfig): AxiosPromise<GetPasswordValidator200Response> {
            return localVarFp.getValidator(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Update an existing Password Validator by name
         * @param {PasswordValidatorApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName(requestParameters: PasswordValidatorApiUpdateByNameRequest, options?: AxiosRequestConfig): AxiosPromise<GetPasswordValidator200Response> {
            return localVarFp.updateByName(requestParameters, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * Request parameters for addNewValidatorToConfig operation in PasswordValidatorApi.
 * @export
 * @interface PasswordValidatorApiAddNewValidatorToConfigRequest
 */
export type PasswordValidatorApiAddNewValidatorToConfigRequest = {
    
} & AddPasswordValidatorRequest

/**
 * Request parameters for deleteValidator operation in PasswordValidatorApi.
 * @export
 * @interface PasswordValidatorApiDeleteValidatorRequest
 */
export type PasswordValidatorApiDeleteValidatorRequest = {
    
    /**
    * Name of the Password Validator
    * @type {string}
    * @memberof PasswordValidatorApiDeleteValidator
    */
    readonly passwordValidatorName: string
    
}

/**
 * Request parameters for getAllValidators operation in PasswordValidatorApi.
 * @export
 * @interface PasswordValidatorApiGetAllValidatorsRequest
 */
export type PasswordValidatorApiGetAllValidatorsRequest = {
    
    /**
    * SCIM filter
    * @type {string}
    * @memberof PasswordValidatorApiGetAllValidators
    */
    readonly filter?: string
    
}

/**
 * Request parameters for getValidator operation in PasswordValidatorApi.
 * @export
 * @interface PasswordValidatorApiGetValidatorRequest
 */
export type PasswordValidatorApiGetValidatorRequest = {
    
    /**
    * Name of the Password Validator
    * @type {string}
    * @memberof PasswordValidatorApiGetValidator
    */
    readonly passwordValidatorName: string
    
}

/**
 * Request parameters for updateByName operation in PasswordValidatorApi.
 * @export
 * @interface PasswordValidatorApiUpdateByNameRequest
 */
export type PasswordValidatorApiUpdateByNameRequest = {
    
    /**
    * Name of the Password Validator
    * @type {string}
    * @memberof PasswordValidatorApiUpdateByName
    */
    readonly passwordValidatorName: string
    
} & UpdateRequest

/**
 * PasswordValidatorApiGenerated - object-oriented interface
 * @export
 * @class PasswordValidatorApiGenerated
 * @extends {BaseAPI}
 */
export class PasswordValidatorApiGenerated extends BaseAPI {
    /**
     * 
     * @summary Add a new Password Validator to the config
     * @param {PasswordValidatorApiAddNewValidatorToConfigRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof PasswordValidatorApiGenerated
     */
    public addNewValidatorToConfig(requestParameters: PasswordValidatorApiAddNewValidatorToConfigRequest, options?: AxiosRequestConfig) {
        return PasswordValidatorApiFp(this.configuration).addNewValidatorToConfig(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete a Password Validator
     * @param {PasswordValidatorApiDeleteValidatorRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof PasswordValidatorApiGenerated
     */
    public deleteValidator(requestParameters: PasswordValidatorApiDeleteValidatorRequest, options?: AxiosRequestConfig) {
        return PasswordValidatorApiFp(this.configuration).deleteValidator(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a list of all Password Validator objects
     * @param {PasswordValidatorApiGetAllValidatorsRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof PasswordValidatorApiGenerated
     */
    public getAllValidators(requestParameters: PasswordValidatorApiGetAllValidatorsRequest = {}, options?: AxiosRequestConfig) {
        return PasswordValidatorApiFp(this.configuration).getAllValidators(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a single Password Validator
     * @param {PasswordValidatorApiGetValidatorRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof PasswordValidatorApiGenerated
     */
    public getValidator(requestParameters: PasswordValidatorApiGetValidatorRequest, options?: AxiosRequestConfig) {
        return PasswordValidatorApiFp(this.configuration).getValidator(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Update an existing Password Validator by name
     * @param {PasswordValidatorApiUpdateByNameRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof PasswordValidatorApiGenerated
     */
    public updateByName(requestParameters: PasswordValidatorApiUpdateByNameRequest, options?: AxiosRequestConfig) {
        return PasswordValidatorApiFp(this.configuration).updateByName(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }
}
