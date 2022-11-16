/*
 * Created by Trevor Sears <trevor@trevorsears.com> (https://trevorsears.com/).
 * 7:36 PM -- November 15th, 2022
 * Project: tsjwt
 */

import { JSONWebToken } from "../jwt/json-web-token.js";

describe("alg: HS256", (): void => {
	
	const jwt: JSONWebToken = new JSONWebToken(
		{
			user: "johns",
			admin: false,
		},
		"hunter2",
		"HS256",
		{
			"alg": "HS256",
			"typ": "JWT"
		}
	);
	
	test("Encoded header string is correctly generated", (): void => {
		
		expect(jwt.getEncodedHeaders())
			.toBe("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
		
	});
	
	test("Encoded payload string is correctly generated", (): void => {
		
		expect(jwt.getEncodedPayload())
			.toBe("eyJ1c2VyIjoiam9obnMiLCJhZG1pbiI6ZmFsc2V9");
		
	});
	
	test("Signature is correctly generated", (): void => {
		
		expect(jwt.getSignature())
			.toBe("YcH3yvIn1HCvHytglkECHorhB4ODpeo3rWHDx2Qsof4");
		
	});
	
	test("Full JWT string is correctly generated", (): void => {
		
		expect(jwt.toString())
			.toBe("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiam9obnMiLCJhZG1pbiI6ZmFsc2V9.YcH3yvIn1HCvHytglkECHorhB4ODpeo3rWHDx2Qsof4")
		
	});
	
});
