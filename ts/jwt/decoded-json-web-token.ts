/*
 * Created by Trevor Sears <trevor@trevorsears.com> (https://trevorsears.com/).
 * 9:02 PM -- November 7th, 2022
 * Project: tsjwt
 */

import { AbstractJSONWebToken } from "./abstract-json-web-token";
import { JWTParsingError } from "../error/jwt-parsing-error";
import { JSONWebTokenHeaders, JSONWebTokenPayload } from "../types/jwt-types";
import { JSONPrimitive } from "../types/json-types";
import { JWTValidationError } from "../error/jwt-validation-error";

/**
 * An object specifying various options related to the JWT validation process.
 */
export type ValidationOptions = {
	
	/**
	 * An array of allowable issuers.
	 * 
	 * The 'iss' (issuer) field of the given incoming JWT will be checked
	 * against the values of this array.
	 * 
	 * In cases in which the 'iss' field of the incoming JWT is populated, the
	 * JWT will only be allowed in the case that a matching value is found in
	 * this array.
	 * 
	 * In order to allow JWTs with either an unpopulated 'iss' field, or no
	 * 'iss' field at all, `undefined` should be present in this array.
	 * 
	 * In order to disable this check entirely, set this field to false.
	 */
	allowableIssuers: Array<JSONPrimitive | undefined> | false,
	
	/**
	 * An array of allowable subjects.
	 *
	 * The 'sub' (subject) field of the given incoming JWT will be checked
	 * against the values of this array.
	 *
	 * In cases in which the 'sub' field of the incoming JWT is populated, the
	 * JWT will only be allowed in the case that a matching value is found in
	 * this array.
	 *
	 * In order to allow JWTs with either an unpopulated 'sub' field, or no
	 * 'sub' field at all, `undefined` should be present in this array.
	 *
	 * In order to disable this check entirely, set this field to false.
	 */
	allowableSubjects: Array<JSONPrimitive | undefined> | false,
	
	/**
	 * An array of allowable subjects.
	 *
	 * The 'sub' (subject) field of the given incoming JWT will be checked
	 * against the values of this array.
	 *
	 * In cases in which the 'sub' field of the incoming JWT is populated, the
	 * JWT will only be allowed in the case that a matching value is found in
	 * this array.
	 *
	 * In order to allow JWTs with either an unpopulated 'sub' field, or no
	 * 'sub' field at all, `undefined` should be present in this array.
	 * 
	 * In order to disable this check entirely, set this field to false.
	 */
	allowableAudiences: Array<JSONPrimitive | undefined> | false,
	
	/**
	 * A tolerance/'grace period', defined in seconds, that indicates the
	 * allowable extra time granted around timing cutoffs such as the 'exp'
	 * (expiration time), 'nbf' (not before),  or 'iat' (issued at) claims.
	 * 
	 * @see ValidationOptions.validateExpirationTimeClaim
	 * @see ValidationOptions.validateNotBeforeClaim
	 * @see ValidationOptions.validateIssuedAtClaim
	 */
	timingTolerance: number,
	
	/**
	 * A boolean value indicating whether the 'exp' (expiration time) claim on
	 * incoming JWTs should be validated.
	 * 
	 * Validation consists of ensuring that the following is true:
	 * ```
	 * expiration time >= current time + timing tolerance
	 * ```
	 *
	 * This is a standard validation, and as such, is enabled by default.
	 */
	validateExpirationTimeClaim: boolean,
	
	/**
	 * A boolean value indicating whether the 'nbf' (not before) claim on
	 * incoming JWTs should be validated.
	 *
	 * Validation consists of ensuring that the following is true:
	 * ```
	 * current time - timing tolerance <= not before time
	 * ```
	 * 
	 * This is a standard validation, and as such, is enabled by default.
	 */
	validateNotBeforeClaim: boolean,
	
	/**
	 * A boolean value indicating whether the 'iat' (issued at) claim on
	 * incoming JWTs should be validated.
	 *
	 * Validation consists of ensuring that the following is true:
	 * ```
	 * current time - timing tolerance <= issued at
	 * ```
	 * 
	 * This is a non-standard validation, and as such, is disabled by default.
	 */
	validateIssuedAtClaim: boolean,
	
};

/**
 * A class for decoding and representing incoming JSON web tokens.
 * 
 * @author Trevor Sears <trevor@trevorsears.com> (https://trevorsears.com/)
 * @version v0.1.0
 * @since v0.1.0
 */
export class DecodedJSONWebToken extends AbstractJSONWebToken {
	
	/**
	 * The raw signature on this decoded JWT, as it was received.
	 */
	protected signature: string;
	
	/**
	 * Initializes a new DecodedJSONWebToken instance with the provided headers,
	 * payload, and signature.
	 * 
	 * @param {JSONWebTokenHeaders} headers The headers object belonging to this
	 * decoded JWT.
	 * @param {JSONWebTokenPayload} payload The payload object belonging to this
	 * decoded JWT.
	 * @param {string} signature The raw signature on this decoded JWT, as it
	 * was received.
	 */
	protected constructor(headers: JSONWebTokenHeaders,
						  payload: JSONWebTokenPayload, signature: string) {
		
		super(headers, payload);
		
		this.signature = signature;
		
	}
	
	/**
	 * Returns the default set of options for processing and validating incoming
	 * JWTs as being authentic, unexpired, and otherwise 'live'.
	 * 
	 * @returns {ValidationOptions} The default set of options for processing
	 * and validating incoming JWTs.
	 */
	public static getDefaultValidationOptions(): ValidationOptions {
		
		return {
			allowableIssuers: false,
			allowableSubjects: false,
			allowableAudiences: false,
			timingTolerance: 0,
			validateExpirationTimeClaim: true,
			validateNotBeforeClaim: true,
			validateIssuedAtClaim: false,
		};
		
	}
	
	/**
	 * Returns a new DecodedJSONWebToken instance, having been built from the
	 * provided token string, and optionally having been verified using the
	 * provided {@link ValidationOptions}.
	 * 
	 * @param {string} token The string token that will be used to construct the
	 * returned DecodedJSONWebToken instance.
	 * @param {boolean} validateBeforeReturn A boolean value indicating whether
	 * or not this method should validate the contents of the incoming JWT
	 * before returning it to the caller. Defaults to `true`.
	 * @param {string} secret The supposed secret against which the signature on
	 * the provided JWT will be checked, if the validateBeforeReturn parameter
	 * is set to `true`.
	 * @param {Partial<ValidationOptions>} options An optional object containing
	 * various options related to the validation of the provided incoming JWT.
	 * @returns {DecodedJSONWebToken} A new DecodedJSONWebToken instance, having
	 * been built from the provided token string.
	 * @see ValidationOptions For more information regarding the options that
	 * are available for the validation process.
	 */
	public static from(token: string,
					   validateBeforeReturn: boolean = true,
					   secret?: string,
					   options: Partial<ValidationOptions> = {},
	): DecodedJSONWebToken {
		
		// Trim extra whitespace off.
		token = token.trim();
		
		const firstSeparatorIndex: number = token.indexOf(".");
		
		if (firstSeparatorIndex === -1) {
			
			throw new JWTParsingError("failed to find first dot separator");
			
		}
		
		const secondSeparatorIndex: number =
			token.indexOf(".", firstSeparatorIndex + 1);
		
		if (secondSeparatorIndex === -1) {
			
			throw new JWTParsingError("failed to find second dot separator");
			
		}
		
		const encodedHeaders: string = token.substring(0, firstSeparatorIndex);
		
		if (encodedHeaders.length === 0) {
			
			throw new JWTParsingError(
				"the headers portion of the JWT was found to be " +
				"zero-length/empty"
			);
			
		}
		
		const encodedPayload: string =
			token.substring(firstSeparatorIndex + 1, secondSeparatorIndex);
		
		if (encodedPayload.length === 0) {
			
			throw new JWTParsingError(
				"the payload portion of the JWT was found to be " +
				"zero-length/empty"
			);
			
		}
		
		const signature: string = token.substring(secondSeparatorIndex + 1);
		
		if (signature.length === 0) {
			
			throw new JWTParsingError(
				"the signature portion of the JWT was found to be " +
				"zero-length/empty"
			);
			
		}
		
		let headers: JSONWebTokenHeaders;
		
		try {
			
			const decodedHeadersJSON: string =
				Buffer.from(encodedHeaders, "base64url").toString()
			
			headers = JSON.parse(decodedHeadersJSON);
			
		} catch (error: any) {
			
			throw new JWTParsingError(
				"failed to decode and/or parse the headers portion of the JWT"
			);
			
		}
		
		let payload: JSONWebTokenPayload;
		
		try {
			
			const decodedPayloadJSON: string =
				Buffer.from(encodedPayload, "base64url").toString()
			
			payload = JSON.parse(decodedPayloadJSON);
			
		} catch (error: any) {
			
			throw new JWTParsingError(
				"failed to decode and/or parse the payload portion of the JWT"
			);
			
		}
		
		const result: DecodedJSONWebToken = new DecodedJSONWebToken(
			headers, payload, signature
		);
		
		if (validateBeforeReturn) result.validate(options);
		
		return result;
		
	}
	
	// DOC-ME [11/10/2022 @ 4:51 PM] Documentation is required!
	// TODO [11/10/2022 @ 4:51 PM] Get rid of #from and move that method into
	//     this one.
	public static decode(token: string,
						 validateBeforeReturn: boolean = true,
						 options: Partial<ValidationOptions> = {},
	): DecodedJSONWebToken {
		
		return DecodedJSONWebToken.from(token, validateBeforeReturn, options);
		
	}
	
	/**
	 * Validates the contents of this DecodedJSONWebToken against the provided
	 * secret, using the options as specified by the caller. This method will
	 * throw an error if this JWT is found to be invalid/inauthentic. 
	 * 
	 * @param {string} secret The secret against which to validate the signature
	 * on this JWT.
	 * @param {Partial<ValidationOptions>} options An optional object containing
	 * various options related to the validation of the provided incoming JWT.
	 */
	public validate(secret: string,
					options: Partial<ValidationOptions> = {}): void {
		
		const fullOptions: ValidationOptions = {
			...DecodedJSONWebToken.getDefaultValidationOptions(),
			...options
		};
		
		if (fullOptions.allowableIssuers !== false) {
			
			const isIssuerAllowed: boolean =
				fullOptions.allowableIssuers.includes(
					this.payload.iss as string | undefined
				);
			
			if (!isIssuerAllowed) {
				
				throw new JWTValidationError(
					`disallowed issuer: ${this.payload.iss}`
				);
				
			}
			
		}
		
		if (fullOptions.allowableSubjects !== false) {
			
			const isSubjectAllowed: boolean =
				fullOptions.allowableSubjects.includes(
					this.payload.sub as string | undefined
				);
			
			if (!isSubjectAllowed) {
				
				throw new JWTValidationError(
					`disallowed subject: ${this.payload.sub}`
				);
				
			}
			
		}
		
		if (fullOptions.allowableAudiences !== false) {
			
			const isAudienceAllowed: boolean =
				fullOptions.allowableAudiences.includes(
					this.payload.aud as string | undefined
				);
			
			if (!isAudienceAllowed) {
				
				throw new JWTValidationError(
					`disallowed audience: ${this.payload.aud}`
				);
				
			}
			
		}
		
		if (fullOptions.validateExpirationTimeClaim) {
			
			if (this.payload.exp === undefined) {
				
				throw new JWTValidationError(
					"the 'exp' claim was found to be undefined"
				);
				
			}
			
			if (typeof this.payload.exp !== "number") {
				
				throw new JWTValidationError(
					"the 'exp' claim was found to be non-numeric"
				);
				
			}
			
			const currentTime: number = Date.now() / 1000;
			
			const isExpired: boolean = 
				this.payload.exp < currentTime + fullOptions.timingTolerance;
			
			if (isExpired) {
				
				throw new JWTValidationError(
					"the 'exp' claim indicates that this JWT is expired"
				);
				
			}
			
		}
			
		if (fullOptions.validateNotBeforeClaim) {
			
			if (this.payload.nbf === undefined) {
				
				throw new JWTValidationError(
					"the 'nbf' claim was found to be undefined"
				);
				
			}
			
			if (typeof this.payload.nbf !== "number") {
				
				throw new JWTValidationError(
					"the 'nbf' claim was found to be non-numeric"
				);
				
			}
			
			const currentTime: number = Date.now() / 1000;
			
			const isBeforeNotBeforeTime: boolean =
				currentTime - fullOptions.timingTolerance < this.payload.nbf;
			
			if (isBeforeNotBeforeTime) {
				
				throw new JWTValidationError(
					"the 'nbf' claim indicates that this JWT is not yet valid"
				);
				
			}
			
		}
			
		if (fullOptions.validateIssuedAtClaim) {
			
			if (this.payload.iat === undefined) {
				
				throw new JWTValidationError(
					"the 'iat' claim was found to be undefined"
				);
				
			}
			
			if (typeof this.payload.iat !== "number") {
				
				throw new JWTValidationError(
					"the 'iat' claim was found to be non-numeric"
				);
				
			}
			
			const currentTime: number = Date.now() / 1000;
			
			const isBeforeIssuedAtTime: boolean =
				currentTime - fullOptions.timingTolerance < this.payload.iat;
			
			if (isBeforeIssuedAtTime) {
				
				throw new JWTValidationError(
					"the 'iat' claim indicates that this JWT has not been " +
					"issued yet"
				);
				
			}
			
		}
		
	}
	
	/**
	 * Returns the raw signature on this decoded JWT, as it was received.
	 * 
	 * @returns {string} The raw signature on this decoded JWT, as it was
	 * received.
	 */
	public getSignature(): string {
		
		return this.signature;
		
	}
	
}
