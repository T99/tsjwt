/*
 * Created by Trevor Sears <trevor@trevorsears.com> (https://trevorsears.com/).
 * 10:47 AM -- November 8th, 2022
 * Project: tsjwt
 */

export class JWTValidationError extends Error {
	
	public constructor(message: string) {
		
		super(`Failed to validate JWT - ${message}.`);
		
	}
	
}
