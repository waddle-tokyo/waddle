import * as crypto from "node:crypto";
import * as net from "node:net";

import * as loginApi from "../apis/auth/login.js";
import * as loginChallengeApi from "../apis/auth/loginChallenge.js";
import * as signupApi from "../apis/auth/signup.js";
import * as api from "../apis/defs.js";
import * as v from "../apis/validator.js";
import * as configuration from "./configuration.js";
import * as db from "./db.js";
import { LoginChallenges } from "./impl/auth/challenges.js";
import * as secrets from "./secrets.js";
import * as server from "./server.js";
import * as test from "./test.js";

// This environment variable is provided by the
// ```
// npx firebase emulator:exec --only firestore ......
// ```
// command.
const firestoreHost = process.env.FIRESTORE_EMULATOR_HOST;
if (!firestoreHost) {
	throw new Error("expected FIRESTORE_EMULATOR_HOST environment variable to be set to the firestore emulator host");
}

async function generateLoginChallengeSecret(): Promise<Uint8Array> {
	const signatureAlgorithmParameters = {
		name: "ECDSA",
		namedCurve: "P-521",
	};

	const keyPair = await crypto.subtle.generateKey(
		signatureAlgorithmParameters,
		true,
		["sign", "verify"],
	);

	const exportedPrivate = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
	const exportedPublic = await crypto.subtle.exportKey("jwk", keyPair.publicKey);

	const text = JSON.stringify({
		public: exportedPublic,
		private: exportedPrivate,
	});

	return new TextEncoder().encode(text);
}

async function generateSignInKeyPair(
	password: string,
) {
	// Generate a key-pair using the password.
	const passwordSalt = crypto.getRandomValues(new Uint8Array(16));
	const passwordAsKey = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(password),
		"PBKDF2",
		false,
		["deriveKey"],
	);

	const passwordHashParams = {
		name: "PBKDF2" as const,
		hash: "SHA-512" as const,
		salt: passwordSalt,
		iterations: 800_000,
	};

	const passwordBasedEncryptionKey = await crypto.subtle.deriveKey(
		passwordHashParams,
		passwordAsKey,
		{
			name: "AES-GCM",
			length: 256,
		},
		false,
		["encrypt", "decrypt", "wrapKey", "unwrapKey"],
	);

	const signatureAlgorithmParameters = {
		name: "ECDSA",
		namedCurve: "P-521",
	} as const;

	const loginVerifyingKeyPair = await crypto.subtle.generateKey(
		signatureAlgorithmParameters,
		true,
		["sign", "verify"],
	);

	const publicKeyJson = await crypto.subtle.exportKey("jwk", loginVerifyingKeyPair.publicKey);
	const wrappingIv = await crypto.getRandomValues(new Uint8Array(12));
	const privateKeyEncryptionParameters = {
		name: "AES-GCM",
		iv: wrappingIv,
		tagLength: 128,
	} as const;
	const encryptedPrivateKey = new Uint8Array(
		await crypto.subtle.wrapKey(
			"jwk",
			loginVerifyingKeyPair.privateKey,
			passwordBasedEncryptionKey,
			privateKeyEncryptionParameters,
		)
	);

	const signatureParameters = {
		name: "ECDSA",
		hash: "SHA-512",
	} as const;

	async function signer(text: string) {
		const bytes = new TextEncoder().encode(text);

		return new Uint8Array(
			await crypto.subtle.sign(
				signatureParameters,
				loginVerifyingKeyPair.privateKey,
				bytes,
			)
		);
	}

	return {
		passwordHashParams,
		algorithmParameters: signatureAlgorithmParameters,
		signatureParameters,
		publicKeyJson: publicKeyJson as v.Serializable & object,
		privateKeyEncryptionParameters,
		encryptedPrivateKey,
		signer,
	};
}

async function createInvitationCode(): Promise<string> {
	const invitationID = Math.random().toFixed(26).substring(2);
	await db.invitationPath(invitationID).create({
		expires: "2099-01-01T00:00:00Z" as api.Timestamp,
		inviter: "FAKEUSERID" as api.UserID,
		remainingUses: 1,
	} satisfies db.Invitation);
	return invitationID;
}

class Waddle {
	private host: string;
	private corsOrigin: string;

	constructor(p: {
		host: string,
		corsOrigin: string,
	}) {
		this.host = p.host;
		this.corsOrigin = p.corsOrigin;
	}

	async request(
		method: string,
		path: string,
		requestBody: undefined | v.Serializable,
		headers: any,
	): Promise<{ status: number, body: any }> {
		if (!path.startsWith("/")) {
			throw new Error("path must start with `/`, but was `" + path + "`");
		}
		const serialized = requestBody === undefined
			? undefined
			: v.serialize(requestBody);
		console.info(method + " " + path);
		console.info("\t-> " + serialized);
		const connection = await fetch(this.host + path, {
			mode: "cors",
			method,
			headers: {
				Accept: "application/json",
				Origin: this.corsOrigin,
				"Content-Type": requestBody === undefined ? undefined : "application/json",
				...headers,
			},
			body: serialized,
		});
		const text = await connection.text();
		const parsed = text === "" ? null : JSON.parse(text);
		console.info("\t<- " + connection.status + " " + JSON.stringify(parsed));
		return {
			status: connection.status,
			body: parsed,
		};
	}

	async get(path: string, headers?: any): Promise<{ status: number, body: any }> {
		return await this.request("GET", path, undefined, headers);
	}

	async options(path: string, headers?: any): Promise<{ status: number, body: any }> {
		return await this.request("OPTIONS", path, undefined, headers);
	}

	async post(path: string, requestBody: v.Serializable, headers?: any): Promise<{ status: number, body: any }> {
		return await this.request("POST", path, requestBody, headers);
	}
}

async function integrationTest() {
	const config: configuration.Config = {
		auth: {
			loginChallengeEcdsaSecretId: "login-challenge-secret-id",
			sessionDomain: "session.domain"
		},
		web: {
			allowedCorsOrigins: ["http://session.domain"],
			dns: {
				zoneName: "zone"
			},
			apiDomain: ".api.session.domain",
			certificateSecretId: "certificate-secret-id"
		},
	};

	const loginChallengeSecretValue = await generateLoginChallengeSecret();

	const secretsClient = new class FakeSecrets implements secrets.SecretsClient {
		async fetchSecret(secretID: string): Promise<Uint8Array> {
			if (secretID === "login-challenge-secret-id") {
				return loginChallengeSecretValue;
			} else if (secretID === "certificate-secret-id") {
				throw new Error("certificate-secret-id should be unused in integration tests");
			}
			throw new Error("undefined secret `" + secretID + "`");
		}
	};

	const loginChallenges = await LoginChallenges.inject({
		secretsClient,
		authConfig: config.auth,
	});

	const endpoints = await server.endpoints(config, secretsClient, loginChallenges);
	const s = new server.Server(endpoints, config.web, secretsClient);
	const resource = await s.serveHttp();

	const client = new Waddle({
		host: "http://localhost:" + (resource.server.address() as net.AddressInfo).port,
		corsOrigin: "http://session.domain",
	});

	// Verify that the health endpoint works as expected.
	const health = await client.get("/health");
	test.assert(health, "is equal to", {
		status: 200,
		body: {
			status: "healthy",
		},
	});

	// Verify that the 404 handler works as expected.
	const error404 = await client.get("/404");
	test.assert(error404, "is equal to", {
		status: 404,
		body: {
			code: 404,
			reason: "no handler for GET /404",
		},
	});

	// Verify that the signup request validator works.
	const signup400A = await client.post("/auth/signup", {});
	test.assert(signup400A, "is equal to", {
		status: 400,
		body: {
			message: "invitationCode: must be a string (was undefined)",
			path: ["invitationCode"],
		},
	});

	// Verify a non-existent invitation code is rejected.
	const signinUsername = "beta";
	const signinPassword = "gamma";
	const signinKey = await generateSignInKeyPair(signinPassword);

	const signupInvalidInvitationCode = await client.post("/auth/signup", {
		invitationCode: "0".repeat(26),
		displayName: "Alpha",
		login: {
			username: "beta",
			keyCredential: {
				pbkdf2Params: signinKey.passwordHashParams,
				keyPair: {
					signatureParameters: signinKey.signatureParameters,
					algorithmParameters: signinKey.algorithmParameters,
					privateKey: {
						encryptionParameters: signinKey.privateKeyEncryptionParameters,
						encryptedBlob: signinKey.encryptedPrivateKey,
					},
					publicKeyJwt: signinKey.publicKeyJson,
				},
			},
			keyCredentialUsernameChallenge: await signinKey.signer(signinUsername),
		},
	} satisfies signupApi.Request);
	test.assert(signupInvalidInvitationCode, "is equal to", {
		status: 200,
		body: {
			tag: "problem",
			badCode: "not-found",
		},
	});

	// Create an invitation code.
	const invitationCode = await createInvitationCode();

	const signupResponse = await client.post("/auth/signup", {
		invitationCode,
		displayName: "Alpha",
		login: {
			username: "beta",
			keyCredential: {
				pbkdf2Params: signinKey.passwordHashParams,
				keyPair: {
					signatureParameters: signinKey.signatureParameters,
					algorithmParameters: signinKey.algorithmParameters,
					privateKey: {
						encryptionParameters: signinKey.privateKeyEncryptionParameters,
						encryptedBlob: signinKey.encryptedPrivateKey,
					},
					publicKeyJwt: signinKey.publicKeyJson,
				},
			},
			keyCredentialUsernameChallenge: await signinKey.signer(signinUsername),
		},
	} satisfies signupApi.Request);
	test.assert(signupResponse, "is equal to", {
		status: 200,
		body: {
			tag: "created",
			userID: test.specPredicate(t => typeof t === "string" || []),
			// No inviter is returned because the user is not found after
			// fetch the ID.
		},
	});

	// Create a login challenge.
	const loginChallengeResponse = await client.post("/auth/login-challenge", {
		username: signinUsername,
	} satisfies loginChallengeApi.Request);
	test.assert(loginChallengeResponse.status, "is equal to", 200);
	const loginChallenge = loginChallengeResponse.body.loginChallenge;

	// Attempt to login by signing the wrong challenge.
	const loginWrongChallenge = await client.post("/auth/login", {
		username: signinUsername,
		loginChallenge: "wrong-challenge",
		loginECDSASignature: await signinKey.signer("wrong-challenge"),
	} satisfies loginApi.Request);
	test.assert(loginWrongChallenge, "is equal to", {
		status: 200,
		body: {
			tag: "failure",
			reason: "challenge",
		},
	});

	// Login using the real challenge.
	const loginSuccess = await client.post("/auth/login", {
		username: signinUsername,
		loginChallenge: loginChallenge,
		loginECDSASignature: await signinKey.signer(loginChallenge),
	} satisfies loginApi.Request);
	test.assert(loginSuccess, "is equal to", {
		status: 200,
		body: {
			tag: "success",
			firebaseToken: test.anyString,
		},
	});

	const notFoundOptionsResponse = await client.options("/404");
	test.assert(notFoundOptionsResponse.status, "is equal to", 204);

	const notFoundPostResponse = await client.post("/404", {});
	test.assert(notFoundPostResponse.status, "is equal to", 404);

	const notFoundGetResponse = await client.get("/404");
	test.assert(notFoundGetResponse.status, "is equal to", 404);

	console.info("closing server");
	resource.server.close();
}

integrationTest();
