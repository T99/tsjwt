/*
 * Created by Trevor Sears <trevor@trevorsears.com> (https://trevorsears.com/).
 * 12:07 PM -- November 15th, 2022
 * Project: tsjwt
 */

import { DecodedJSONWebToken } from "../jwt/decoded-json-web-token.js";

describe("Secret validation", (): void => {
	
	test("Valid secret passes secret validation", (): void => {
		
		const token: DecodedJSONWebToken = DecodedJSONWebToken.decode(
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.o-OtYZq9ArTjEdIqvQ2c4_ona8xoneNHB0icQiOzf_Y",
			false
		);
		
		const expectedSecret: string = "heres_the_secret";
		
		expect(token.validateSecret(expectedSecret)).toBeTruthy();
		
	});
	
	test("Invalid secret DOES NOT pass secret validation", (): void => {
		
		const token: DecodedJSONWebToken = DecodedJSONWebToken.decode(
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.o-OtYZq9ArTjEdIqvQ2c4_ona8xoneNHB0icQiOzf_Y",
			false
		);
		
		const expectedSecret: string = "wrong-secret";
		
		expect(token.validateSecret(expectedSecret)).toBeFalsy();
		
	});
	
});
