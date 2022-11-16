/*
 * Created by Trevor Sears <trevor@trevorsears.com> (https://trevorsears.com/).
 * 7:11 PM -- November 7th, 2022
 * Project: tsjwt
 */

import { JSONObject } from "./json-types.js";

export type HashingAlgorithmIdentifier =
	| "HS256"
	| "HS384"
	| "HS512"
	| "PS256"
	| "PS384"
	| "PS512"
	| "RS256"
	| "RS384"
	| "RS512"
	| "ES256"
	| "ES256K"
	| "ES384"
	| "ES512"
	| "EdDSA";

export const VALID_HASHING_ALGORITHM_IDENTIFIERS:
	HashingAlgorithmIdentifier[] = [
	"HS256",
	"HS384",
	"HS512",
	"PS256",
	"PS384",
	"PS512",
	"RS256",
	"RS384",
	"RS512",
	"ES256",
	"ES256K",
	"ES384",
	"ES512",
	"EdDSA",
];

export const SUPPORTED_HASHING_ALGORITHM_IDENTIFIERS:
	HashingAlgorithmIdentifier[] = [
	"HS256",
	"HS384",
	"HS512",
];

export type HashingAlgorithm = (input: string) => string;

export type JSONWebTokenHeaderField = "alg" | "typ" | string;

export type JSONWebTokenHeaders = JSONObject<JSONWebTokenHeaderField | string>;

export type JSONWebTokenRegisteredClaim =
	| "iss"
	| "sub"
	| "aud"
	| "exp"
	| "nbf"
	| "iat"
	| "jti";

export type JSONWebTokenPayloadField = JSONWebTokenRegisteredClaim | string;

export type JSONWebTokenPayload = JSONObject<JSONWebTokenPayloadField | string>;
