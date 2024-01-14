import * as crypto from "node:crypto";

import * as configuration from "./configuration.js";
import { LoginChallenges } from "./impl/auth/challenges.js";
import * as secrets from "./secrets.js";
import * as server from "./server.js";

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

	console.log("finishing in one minute...");
	setTimeout(() => {
		console.log("done waiting");

		resource.server.close();
	}, 60e3);
}

integrationTest();
