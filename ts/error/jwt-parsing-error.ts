/*
 * Created by Trevor Sears <trevor@trevorsears.com> (https://trevorsears.com/).
 * 9:21 AM -- November 8th, 2022
 * Project: tsjwt
 */

export class JWTParsingError extends Error {
	
	public constructor(message: string) {
		
		super(`Failed to parse JWT from string - ${message}.`);
		
	}
	
}
