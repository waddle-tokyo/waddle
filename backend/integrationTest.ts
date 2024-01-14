import * as crypto from "node:crypto";
import * as net from "node:net";

import * as api from "../apis/defs.js";
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

	async get(path: string, headers?: any): Promise<{ status: number, body: any }> {
		if (!path.startsWith("/")) {
			throw new Error("path must start with `/`, but was `" + path + "`");
		}

		const connection = await fetch(this.host + path, {
			mode: "cors",
			method: "GET",
			headers: {
				Accept: "application/json",
				Origin: this.corsOrigin,
				...headers,
			},
		});
		return {
			status: connection.status,
			body: await connection.json(),
		};
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

	console.info("closing server");
	resource.server.close();
}

integrationTest();
