import * as v from "../apis/validator.js";

const configValidator = new v.Records({
	auth: new v.Records({
		loginChallengeEcdsaSecretId: v.strings,
		sessionDomain: v.strings,
	}),
	web: new v.Records({
		allowedCorsOrigins: v.array(v.strings),
		apiDomain: v.strings,
		dns: new v.Records({
			zoneName: v.strings,
		}),
		certificateSecretId: v.strings,
	}),
});

export type Config = ReturnType<(typeof configValidator)["validate"]>;

export function fromString(contents: string, fileSource: string): Config {
	const configurationString = contents.replace(/^\s*\/\/[^\n]*/g, x => x.replace(/./g, " "));

	const configurationObject = JSON.parse(configurationString);

	return configValidator.validate(configurationObject, [fileSource]);
}
