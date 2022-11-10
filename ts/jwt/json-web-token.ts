/*
 * Created by Trevor Sears <trevor@trevorsears.com> (https://trevorsears.com/).
 * 7:09 PM -- November 7th, 2022
 * Project: tsjwt
 */

import crypto from "crypto";
import {
	HashingAlgorithm,
	HashingAlgorithmIdentifier,
	JSONWebTokenHeaders,
	JSONWebTokenPayload,
} from "../types/jwt-types";
import { AbstractJSONWebToken } from "./abstract-json-web-token";
import {
	DecodedJSONWebToken,
	ValidationOptions
} from "./decoded-json-web-token";

export class JSONWebToken extends AbstractJSONWebToken {
	
	protected hashingAlgorithm: HashingAlgorithmIdentifier;
	
	protected secret: string;
	
	public constructor(payload: JSONWebTokenPayload,
					   secret: string,
					   hashingAlgorithm: HashingAlgorithmIdentifier = "HS256",
					   headers: JSONWebTokenHeaders =
						   JSONWebToken.getDefaultHeaders(hashingAlgorithm)) {
		
		super(headers, payload);
		
		this.hashingAlgorithm = hashingAlgorithm;
		this.secret = secret;
		
	}
	
	public static decode(token: string,
						 validateBeforeReturn: boolean = true,
						 options: Partial<ValidationOptions> = {},
	): DecodedJSONWebToken {
		
		return DecodedJSONWebToken.decode(token, validateBeforeReturn, options);
		
	}
	
	/**
	 * Returns the set of default headers for a JSON web token, optionally
	 * including a field that details the specified hashing algorithm.
	 * 
	 * @param {HashingAlgorithmIdentifier} hashingAlgorithm An optional string
	 * indicating which hashing algorithm is being used while building the
	 * current JWT.
	 * @returns {JSONWebTokenHeaders} A collection of the default JWT headers
	 * for this implementation.
	 */
	public static getDefaultHeaders(
		hashingAlgorithm?: HashingAlgorithmIdentifier): JSONWebTokenHeaders {
		
		const defaultHeaders: JSONWebTokenHeaders = { "typ": "JWT" };
		
		if (hashingAlgorithm !== undefined) {
			
			defaultHeaders["alg"] = hashingAlgorithm;
			
		}
		
		return defaultHeaders;
		
	}
	
	/**
	 * Returns the relevant hashing algorithm/function for this JSON web token,
	 * based on the value of this JWT's `hashingAlgorithm` property.
	 * 
	 * @returns {HashingAlgorithm} The relevant hashing algorithm/function for
	 * this JSON web token.
	 */
	protected getHashingAlgorithm(): HashingAlgorithm {
		
		switch (this.hashingAlgorithm) {
			
			case "HS256":
				return (input: string): string =>
					crypto.createHmac("SHA256", this.getSecret())
						.update(input)
						.digest()
						.toString("base64url");
				
			case "HS384":
				return (input: string): string =>
					crypto.createHmac("SHA384", this.getSecret())
						.update(input)
						.digest()
						.toString("base64url");
			
			case "HS512":
				return (input: string): string =>
					crypto.createHmac("SHA512", this.getSecret())
						.update(input)
						.digest()
						.toString("base64url");
			
			case "PS256":
			case "PS384":
			case "PS512":
			case "RS256":
			case "RS384":
			case "RS512":
			case "ES256":
			case "ES256K":
			case "ES384":
			case "ES512":
			case "EdDSA":
			default:
				throw new Error(
					`Unrecognized hashing algorithm: ${this.hashingAlgorithm}`
				);
			
		}
		
	}
	
	/**
	 * Returns the raw string secret for this JSON web token.
	 * 
	 * @returns {string} The raw string secret for this JSON web token.
	 */
	public getSecret(): string {
		
		return this.secret;
		
	}
	
	/**
	 * Returns the signature for this JSON web token.
	 * 
	 * @returns {string} The signature for this JSON web token.
	 */
	public getSignature(): string {
		
		const hashingFunction: HashingAlgorithm = this.getHashingAlgorithm();
		
		return hashingFunction(
			[this.getEncodedHeaders(), this.getEncodedPayload()].join(".")
		);
		
	}
	
}
