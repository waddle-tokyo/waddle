import type * as api from "../defs.js";
import type * as v from "../validator.js";

export type KeyCredential = {
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
		publicKeyJwt: object & v.Serializable,
	},
};

export type Request = {
	invitationCode: string,

	displayName: string,

	login: {
		username: string,
		keyCredential: KeyCredential,

		/**
		 * The `username` encoded in UTF-8, signed using the private key.
		 */
		keyCredentialUsernameChallenge: Uint8Array,
	},
};

export type ResponseSuccess = {
	tag: "created",
	userID: api.UserID,

	inviter: {
		userID: api.UserID,
		displayName: string | undefined,
	},
};

export type ResponseProblem = {
	tag: "problem",

	badCode?: "not-found" | string,
	badUsername?: "unavailable" | string,
};

export type Response = ResponseSuccess | ResponseProblem;
