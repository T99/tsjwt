/*
 * Created by Trevor Sears <trevor@trevorsears.com> (https://trevorsears.com/).
 * 11:14 AM -- November 8th, 2022
 * Project: tsjwt
 */

import { DecodedJSONWebToken } from "../jwt/decoded-json-web-token.js";
import { JSONWebTokenHeaders, JSONWebTokenPayload } from "../types/jwt-types.js";

describe("Basic decoding tests", (): void => {
	
	const token: string = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJob25rcyIsIm5hbWUiOiJIb25rcyBNY0dlZSIsImlhdCI6MTY2NzkyNDA5Mn0.s52T6YUh_COF3eDyz_M_TGbvpJ_8vYknVuNN7UXv0-E";
	const decodedJWT: DecodedJSONWebToken =
		DecodedJSONWebToken.decode(token, false);
	
	test("Encoded headers string is correctly parsed", (): void => {
		
		expect(decodedJWT.getEncodedHeaders())
			.toBe("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
		
	});
	
	test("Encoded headers string is correctly parsed", (): void => {
		
		expect(decodedJWT.getEncodedPayload())
			.toBe("eyJzdWIiOiJob25rcyIsIm5hbWUiOiJIb25rcyBNY0dlZSIsImlhdCI6MTY2NzkyNDA5Mn0");
		
	});
	
	test("Signature string is correctly parsed", (): void => {
		
		expect(decodedJWT.getSignature())
			.toBe("s52T6YUh_COF3eDyz_M_TGbvpJ_8vYknVuNN7UXv0-E");
		
	});
	
	test("Hashing algorithm parsing succeeds", (): void => {
		
		expect(decodedJWT.getHashingAlgorithmIdentifier())
			.toBe("HS256");
		
	});
	
	test("Headers are correctly decoded/parsed", (): void => {
		
		const headers: JSONWebTokenHeaders = decodedJWT.getHeaders();
		
		expect(headers.alg).toBe("HS256");
		expect(headers.typ).toBe("JWT");
		expect(headers.doesntExist).toBeUndefined();
		expect(headers.notThere).toBeUndefined();
		
	});
	
	test("Payload is correctly decoded/parsed", (): void => {
		
		const payload: JSONWebTokenPayload = decodedJWT.getPayload();
		
		expect(payload.sub).toBe("honks");
		expect(payload.name).toBe("Honks McGee");
		expect(payload.iat).toBe(1667924092);
		expect(payload.doesntExist).toBeUndefined();
		expect(payload.notThere).toBeUndefined();
		
	});
	
});
