/*
 * Created by Trevor Sears <trevor@trevorsears.com> (https://trevorsears.com/).
 * 11:14 AM -- November 8th, 2022
 * Project: tsjwt
 */

import { DecodedJSONWebToken } from "../jwt/decoded-json-web-token";
import { JSONWebTokenHeaders, JSONWebTokenPayload } from "../types/jwt-types";

test("Basic decoding test", (): void => {
	
	const token: string = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJob25rcyIsIm5hbWUiOiJIb25rcyBNY0dlZSIsImlhdCI6MTY2NzkyNDA5Mn0.s52T6YUh_COF3eDyz_M_TGbvpJ_8vYknVuNN7UXv0-E";
	
	const decodedJWT: DecodedJSONWebToken =
		DecodedJSONWebToken.decode(token, false);
	
	const headers: JSONWebTokenHeaders = decodedJWT.getHeaders();
	const payload: JSONWebTokenPayload = decodedJWT.getPayload();
	
	expect(headers.alg).toBe("HS256");
	expect(headers.typ).toBe("JWT");
	expect(payload.sub).toBe("honks");
	expect(payload.name).toBe("Honks McGee");
	expect(payload.iat).toBe(1667924092);
	
});
