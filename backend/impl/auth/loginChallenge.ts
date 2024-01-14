import * as loginChallengeApi from "../../../apis/auth/loginChallenge.js";
import * as apisCommon from "../../../apis/defs.js";
import * as v from "../../../apis/validator.js";
import * as configuration from "../../configuration.js";
import * as db from "../../db.js";
import * as handler from "../../handler.js";
import * as challenges from "./challenges.js";

export class Handler extends handler.Handler<loginChallengeApi.Request, loginChallengeApi.Response>  {
	constructor(
		private loginChallenges: challenges.LoginChallenges,
	) {
		super();
	}

	override validator() {
		return new v.Records({
			username: v.strings,
		});
	}

	override async handle(
		req: handler.APIRequest<loginChallengeApi.Request>,
		trace: handler.ReqContext,
	): Promise<handler.APIResponse<loginChallengeApi.Response>> {
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
			return this.loginChallenges.createChallenge(req.request.username)
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
	}

	static async inject(p: {
		config: configuration.Config,
		loginChallenges: challenges.LoginChallenges,
	}) {
		return new Handler(p.loginChallenges);
	}
};
