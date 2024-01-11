import * as loginChallengeApi from "../../../apis/auth/loginChallenge.js";
import * as apisCommon from "../../../apis/defs.js";
import * as v from "../../../apis/validator.js";
import * as db from "../../db.js";
import * as common from "../../handler.js";
import * as challenges from "./challenges.js";

import { config } from "../../config.js";

export const requestValidator: v.Validator<loginChallengeApi.Request> = new v.Records({
	username: v.strings,
});

const loginChallengesPromise = challenges.initializeLoginChallenges(config.auth.loginChallengeEcdsaSecretId);

export const handler: common.APIHandler<loginChallengeApi.Request, loginChallengeApi.Response> = async (req, trace) => {
	const loginChallenges = await loginChallengesPromise;

	const userDocs = await trace.measureTime("dbRetrieveByUsername", () => {
		return db.userByLoginUsername(req.request.username).get();
	});

	if (userDocs.empty) {
		return {
			body: {
				tag: "failure",
				reason: "credentials-username",
			},
		};
	}
	const userDoc = userDocs.docs[0];
	const user = db.userValidator.validate(userDoc.data(), [`firestore(username=${req.request.username})`]);

	const challenge = await trace.measureTime("createChallenge", () => {
		return loginChallenges.createChallenge(req.request.username)
	});

	trace.includeServerTiming = true;

	return {
		body: {
			tag: "success",
			loginChallenge: challenge.challenge,
			loginChallengeExpiry: challenge.expires.toISOString() as apisCommon.Timestamp,
			keyCredential: {
				pbkdf2Params: user.login.keyCredential.pbkdf2Params,
				keyPair: {
					algorithmParameters: user.login.keyCredential.keyPair.algorithmParameters,
					signatureParameters: user.login.keyCredential.keyPair.signatureParameters,
					privateKey: {
						encryptionParameters: user.login.keyCredential.keyPair.privateKey.encryptionParameters,
						encryptedBlob: user.login.keyCredential.keyPair.privateKey.encryptedBlob,
					},
				},
			},
		} satisfies loginChallengeApi.Response,
	};
};
