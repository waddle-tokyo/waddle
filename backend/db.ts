import * as firebase from "firebase-admin/app";
import * as firestore from "firebase-admin/firestore";

import * as api from "../apis/defs.js";
import * as handler from "./handler.js";
import * as v from "../apis/validator.js";
import * as signupApi from "../apis/auth/signup.js";

firebase.initializeApp({
	credential: firebase.applicationDefault(),
});

export const db = firestore.getFirestore();

export function invitationPath(invitationID: string) {
	if (!/^[A-Z0-9]{26}$/.test(invitationID)) {
		throw new handler.APIError("invalid invitationID", 400);
	}
	return db.doc(`invitations/${invitationID}`);
}

/**
 * Stored at `invitations/{invitationID}`
 */
export type Invitation = {
	expires: api.Timestamp,
	inviter: api.UserID,
	remainingUses: number,
};

export function userByLoginUsername(loginUsername: string) {
	return db.collection("users")
		.where("login.username", "==", loginUsername.toLowerCase());
}

export function userPath(userID: api.UserID) {
	return db.doc(`users/${userID}`);
}

export async function retrieveUser(userID: api.UserID): Promise<User | null> {
	const doc = await userPath(userID).get();
	if (!doc.exists) {
		return null;
	}
	try {
		return userValidator.validate(doc, [`firestore(${doc.ref.path})`]);
	} catch (e) {
		if (e instanceof v.ValidationError) {
			console.error(`retrieveUser: invalid User:`, e);
		}
		throw e;
	}
}

/**
 * Store at `users/{userID}`
 */
export type User = {
	login: {
		username: string,
		keyCredential: signupApi.KeyCredential,
	},
	inviterID: api.UserID,
};

export const userValidator: v.Validator<User> = new v.Records({
	login: new v.Records({
		username: v.strings,
		keyCredential: new v.Records<signupApi.KeyCredential>({
			pbkdf2Params: new v.Records({
				name: new v.LiteralString("PBKDF2"),
				hash: new v.LiteralString("SHA-512"),
				salt: v.hexBytes,
				iterations: v.numbers,
			}),
			keyPair: new v.Records({
				algorithmParameters: new v.Records({
					name: new v.LiteralString("ECDSA"),
					namedCurve: new v.LiteralString("P-521"),
				}),
				signatureParameters: new v.Records({
					name: new v.LiteralString("ECDSA"),
					hash: new v.LiteralString("SHA-512"),
				}),
				privateKey: new v.Records({
					encryptionParameters: new v.Records({
						name: new v.LiteralString("AES-GCM"),
						tagLength: new v.LiteralNumber(128),
						iv: v.hexBytes,
					}),
					encryptedBlob: v.hexBytes,
				}),
				publicKeyJwt: new v.AnyObject(),
			}),
		}),
	}),
	inviterID: v.userID,
});

export function userForFriendsPath(userID: api.UserID) {
	return db.doc(`users-for-friends/${userID}`);
}

/**
 * Stored at `users-for-friends/{userID}`
 */
export type UserForFriends = {
	displayName: string,
};

export function anonDiscoveryPath(name: string) {
	return db.doc(`anon-discovery/${name}`);
}

/**
 * Stored at `anon-discovery/{ID}`
 */
export type AnonDiscovery = {
	type: "api",
	version: string,
	domain: string,
	expires: Date,
};

export function loginSessionPath(sessionID: string) {
	if (!v.HEX_BYTES_REGEX.test(sessionID)) {
		throw new Error("invalid sessionID");
	}
	return db.doc(`sv-sessions/${sessionID}`);
}

export type LoginSession = {
	userID: api.UserID,
	loggedInAt: Date,
	expires: Date,
};
