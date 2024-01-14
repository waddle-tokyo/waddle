import * as crypto from "node:crypto";

import * as firebaseAuth from "firebase-admin/auth";

import * as loginApi from "../../../apis/auth/login.js";
import * as defs from "../../../apis/defs.js";
import * as v from "../../../apis/validator.js";
import * as configuration from "../../configuration.js";
import * as db from "../../db.js";
import * as handler from "../../handler.js";
import * as secrets from "../../secrets.js";
import * as challenges from "./challenges.js";


const LOGIN_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000;

export class Handler extends handler.Handler<loginApi.Request, loginApi.Response> {
	constructor(
		private loginChallenges: challenges.LoginChallenges,
		private authConfig: configuration.Config["auth"],
	) {
		super();
	}

	override validator(): v.Validator<loginApi.Request> {
		return new v.Records({
			username: v.strings,
			loginChallenge: v.strings,
			loginECDSASignature: v.hexBytes,
		});
	}

	override async handle(
		req: handler.APIRequest<loginApi.Request>,
		trace: handler.ReqContext,
	): Promise<handler.APIResponse<loginApi.Response>> {
		const verification = await trace.measureTime("verifyChallenge", () => {
			return this.loginChallenges.verifyChallenge(
				req.request.username,
				req.request.loginChallenge,
			);
		});

		if (verification === "expired") {
			return {
				body: {
					tag: "failure",
					reason: "challenge",
				} satisfies loginApi.ResponseFailure,
			};
		} else if (verification === "invalid") {
			return {
				body: {
					tag: "failure",
					reason: "challenge",
				} satisfies loginApi.ResponseFailure,
			};
		}

		// Retrieve the public key associated with this login.
		const users = await trace.measureTime("dbUserByUsername", () => {
			return db.userByLoginUsername(req.request.username).get();
		});
		const userDoc = users.docs[0];
		if (!userDoc) {
			return {
				body: {
					tag: "failure",
					reason: "credentials-username",
				} satisfies loginApi.ResponseFailure,
			};
		}
		const user = db.userValidator.validate(userDoc.data(), [`firestore(${userDoc.ref.path})`]);
		const userID = userDoc.id as defs.UserID;

		const verifyingKey = await crypto.subtle.importKey(
			"jwk",
			user.login.keyCredential.keyPair.publicKeyJwt as crypto.JsonWebKey,
			user.login.keyCredential.keyPair.algorithmParameters,
			false,
			["verify"],
		);

		const challengeBytes = new TextEncoder().encode(req.request.loginChallenge);

		const verified = await crypto.subtle.verify(
			user.login.keyCredential.keyPair.signatureParameters,
			verifyingKey,
			req.request.loginECDSASignature,
			challengeBytes,
		);
		if (!verified) {
			return {
				body: {
					tag: "failure",
					reason: "credentials-signature",
				} satisfies loginApi.ResponseFailure,
			};
		}

		// Create a session cookie
		const sessionBytes = new Uint8Array(crypto.randomBytes(32));
		const sessionID = v.toHexadecimal(sessionBytes);

		const sessionExpires = new Date(Date.now() + LOGIN_EXPIRY_MS);

		await trace.measureTime("dbCreateLoginSession", () => {
			return db.loginSessionPath(sessionID).create({
				userID,
				loggedInAt: new Date(),
				expires: sessionExpires,
			} satisfies db.LoginSession);
		});

		// Create a Firebase user token
		const firebaseToken = await trace.measureTime("firebaseCreateCustomToken", () => {
			return firebaseAuth.getAuth().createCustomToken(userID);
		});

		trace.includeServerTiming ||= user.debugPermission;

		return {
			body: {
				tag: "success",
				firebaseToken,
			} satisfies loginApi.ResponseSuccess,
			headers: {
				"Set-Cookie": [
					`loginsession=${sessionID}`,
					`Domain=${this.authConfig.sessionDomain}`,
					`Expires=${sessionExpires.toUTCString()}`,
					"HttpOnly",
					"SameSite=Strict",
					"Secure",
				].join("; "),
			},
		};
	}

	static async inject(p: {
		secretsClient: secrets.SecretsClient,
		config: configuration.Config,
	}) {
		const loginChallenges = await challenges.LoginChallenges.inject({
			secretsClient: p.secretsClient,
			authConfig: p.config.auth,
		});
		return new Handler(loginChallenges, p.config.auth);
	}
}
