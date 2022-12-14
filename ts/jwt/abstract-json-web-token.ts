/*
 * Created by Trevor Sears <trevor@trevorsears.com> (https://trevorsears.com/).
 * 9:02 PM -- November 7th, 2022
 * Project: tsjwt
 */

import {
	HashingAlgorithmIdentifier,
	JSONWebTokenHeaders,
	JSONWebTokenPayload,
	JSONWebTokenPayloadField,
	SUPPORTED_HASHING_ALGORITHM_IDENTIFIERS,
	VALID_HASHING_ALGORITHM_IDENTIFIERS,
} from "../types/jwt-types.js";
import { JWTParsingError } from "../error/jwt-parsing-error.js";

export abstract class AbstractJSONWebToken {
	
	protected headers: JSONWebTokenHeaders;
	
	protected payload: JSONWebTokenPayload;
	
	protected constructor(headers: JSONWebTokenHeaders,
						  payload: JSONWebTokenPayload) {
		
		this.headers = headers;
		this.payload = payload;
		
	}
	
	/**
	 * Returns the JSON/object set of headers for this JSON web token.
	 *
	 * @returns {JSONWebTokenHeaders} The JSON/object set of headers for this
	 * JSON web token.
	 */
	public getHeaders(): JSONWebTokenHeaders {
		
		return this.headers;
		
	}
	
	/**
	 * Returns the base64url encoded set of headers for this JSON web token.
	 *
	 * @returns {string} The base64url encoded set of headers for this JSON web
	 * token.
	 */
	public getEncodedHeaders(): string {
		
		return Buffer.from(
			JSON.stringify(this.getHeaders())
		).toString("base64url");
		
	}
	
	public getHashingAlgorithmIdentifier(): HashingAlgorithmIdentifier {
		
		const headers: JSONWebTokenHeaders = this.getHeaders();
		
		if (headers.alg === undefined) {
			
			throw new JWTParsingError(
				"Attempting to discern the hashing algorithm used on a JWT, " +
				"but found the 'alg' header field to be undefined."
			);
			
		} else if (!VALID_HASHING_ALGORITHM_IDENTIFIERS.includes(
			headers.alg as HashingAlgorithmIdentifier
		)) {
			
			throw new JWTParsingError(
				"Attempting to discern the hashing algorithm used on a JWT, " +
				"but found the 'alg' header field to specify an invalid " +
				`hashing algorithm: '${headers.alg}'.`
			);
			
		} else if (!SUPPORTED_HASHING_ALGORITHM_IDENTIFIERS.includes(
			headers.alg as HashingAlgorithmIdentifier
		)) {
			
			throw new JWTParsingError(
				"Attempting to discern the hashing algorithm used on a JWT, " +
				"but found the 'alg' header field to specify a valid but " +
				`unsupported hashing algorithm: '${headers.alg}'.`
			);
			
		}
		
		return headers.alg as HashingAlgorithmIdentifier;
		
	}
	
	/**
	 * Sets the specified field on the payload of this JSON web token to the
	 * specified value.
	 *
	 * @param {JSONWebTokenPayloadField} field The field to set on the payload
	 * of this JSON web token.
	 * @param {string} value The value to set the specified field to.
	 */
	public setPayloadField(field: JSONWebTokenPayloadField,
						   value: string): void {
		
		this.payload[field] = value;
		
	}
	
	/**
	 * Returns the JSON/object payload for this JSON web token.
	 *
	 * @returns {JSONWebTokenPayload} The JSON/object payload for this JSON web
	 * token.
	 */
	public getPayload(): JSONWebTokenPayload {
		
		return this.payload;
		
	}
	
	/**
	 * Returns the base64url encoded payload for this JSON web token.
	 *
	 * @returns {string} The base64url encoded payload for this JSON web token.
	 */
	public getEncodedPayload(): string {
		
		return Buffer.from(
			JSON.stringify(this.getPayload())
		).toString("base64url");
		
	}
	
	/**
	 * Returns the hashed/encoded signature for this JSON web token.
	 *
	 * @returns {string} The hashed/encoded signature for this JSON web token.
	 */
	public abstract getSignature(): string;
	
	/**
	 * Returns the string version of this JSON web token.
	 *
	 * @returns {string} The string version of this JSON web token.
	 */
	public toString(): string {
		
		return [
			this.getEncodedHeaders(),
			this.getEncodedPayload(),
			this.getSignature(),
		].join(".");
		
	}
	
}
