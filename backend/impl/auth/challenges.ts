import * as crypto from "node:crypto";

import * as secrets from "../../secrets.js";
import * as v from "../../../apis/validator.js";

export class LoginChallenges {
	constructor(
		private keyPair: {
			signing: crypto.webcrypto.CryptoKey,
			verifying: crypto.webcrypto.CryptoKey
		},
	) { }

	private ecdsaParams: crypto.webcrypto.EcdsaParams = {
		name: "ECDSA",
		hash: "SHA-512",
	};

	async createChallenge(userID: string): Promise<{ challenge: string, expires: Date }> {
		const expires = Date.now() + 1000 * 60 * 5;
		const json = v.serialize({
			userID: userID,
			expires,
		});
		const guarded = new TextEncoder().encode(json);
		const signature = await crypto.subtle.sign(this.ecdsaParams, this.keyPair.signing, guarded);

		return {
			challenge: v.toHexadecimal(new Uint8Array(signature)) + "/" + json,
			expires: new Date(expires),
		};
	}

	async verifyChallenge(userID: string, challenge: string): Promise<"invalid" | "expired" | "ok"> {
		const match = challenge.match(/^((?:[0-9a-f]{2})+)\/(.+)$/);
		if (!match) {
			return "invalid";
		}
		const challengeSignature = match[1];
		const challengePayload = match[2];

		const guarded = new TextEncoder().encode(challengePayload);
		const signature = v.fromHexadecimal(challengeSignature);
		const verified = await crypto.subtle.verify(
			this.ecdsaParams,
			this.keyPair.verifying,
			signature,
			guarded,
		);
		if (!verified) {
			return "invalid";
		}

		try {
			const x = JSON.parse(challengePayload);
			if (x.userID !== userID) {
				return "invalid";
			}
			const expires = x.expires;
			if (typeof expires !== "number" || !isFinite(expires)) {
				return "invalid";
			}
			if (expires < Date.now()) {
				return "expired";
			}
			return "ok";
		} catch (e) {
			return "invalid";
		}
	}
}

export async function initializeLoginChallenges(loginChallengeEcdsaSecretId: string) {
	const challengeSigningKeyPair = JSON.parse(
		new TextDecoder()
			.decode(await secrets.secretsClient.fetchSecret(loginChallengeEcdsaSecretId))
	);

	const challengeSigningKey = await crypto.subtle.importKey("jwk", challengeSigningKeyPair.private, {
		name: "ECDSA",
		namedCurve: "P-521",
	}, false, ["sign"]);

	const challengeVerifyingKey = await crypto.subtle.importKey("jwk", challengeSigningKeyPair.public, {
		name: "ECDSA",
		namedCurve: "P-521",
	}, false, ["verify"]);

	return new LoginChallenges({
		signing: challengeSigningKey,
		verifying: challengeVerifyingKey,
	});
}
