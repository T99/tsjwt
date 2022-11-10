/*
 * Created by Trevor Sears <trevor@trevorsears.com> (https://trevorsears.com/).
 * 8:11 PM -- November 7th, 2022
 * Project: tsjwt
 */

export type JSONPrimitive = string | number | boolean | null;

export type JSONObject<K extends string = string> = { [key in K]?: JSONValue };

export type JSONArray = JSONValue[];

export type JSONValue = JSONObject | JSONArray | JSONPrimitive;
