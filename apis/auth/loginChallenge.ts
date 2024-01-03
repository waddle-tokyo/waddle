import type * as api from "../defs.js";

export type Request = {
	username: string,
};

export type ResponseFailure = {
	tag: "failure",
	reason: "credentials-username",
};

export type ResponseSuccess = {
	tag: "success",

	loginChallenge: string,
	loginChallengeExpiry: api.Timestamp,

	keyCredential: {
		pbkdf2Params: {
			name: "PBKDF2",
			hash: "SHA-512",
			salt: Uint8Array,
			iterations: number,
		},
		keyPair: {
			algorithmParameters: {
				name: "ECDSA",
				namedCurve: "P-521",
			},
			signatureParameters: {
				name: "ECDSA",
				hash: "SHA-512",
			},
			privateKey: {
				encryptionParameters: {
					name: "AES-GCM",
					iv: Uint8Array,
					tagLength: 128,
				},
				encryptedBlob: Uint8Array,
			},
		},
	},
};

export type Response = ResponseSuccess | ResponseFailure;
