import * as fs from "node:fs";

import * as v from "../apis/validator.js";

const CONFIG_FILE = "conf.jsonc";

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

const commentedConfigurationString = fs.readFileSync(CONFIG_FILE, "utf-8");

const configurationString = commentedConfigurationString.replace(/\/\/[^\n]*/g, x => x.replace(/./g, " "));

const configurationObject = JSON.parse(configurationString);

export const config = configValidator.validate(configurationObject, [CONFIG_FILE]);
