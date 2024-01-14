import * as crypto from "node:crypto";

import { FieldValue } from "firebase-admin/firestore";
import { ulid } from "ulid";

import type * as signupApi from "../../../apis/auth/signup.js";
import { UserID } from "../../../apis/defs.js";
import * as v from "../../../apis/validator.js";
import * as db from "../../db.js";
import * as handler from "../../handler.js";

export class Handler extends handler.Handler<signupApi.Request, signupApi.Response> {
	constructor() {
		super();
	}

	override validator(): v.Validator<signupApi.Request> {
		return new v.Records({
			invitationCode: v.strings.regex(/^[A-Z0-9]{26}$/),
			displayName: v.strings,
			login: new v.Records({
				username: v.strings.regex(/^[a-zA-Z][a-zA-Z0-9_]{2,319}$/),
				keyCredential: new v.Records({
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
							encryptedBlob: v.hexBytes,
							encryptionParameters: new v.Records({
								name: new v.LiteralString("AES-GCM"),
								iv: v.hexBytes,
								tagLength: new v.LiteralNumber(128),
							}),
						}),
						publicKeyJwt: new v.AnyObject(),
					}),
				}),
				keyCredentialUsernameChallenge: v.hexBytes,
			})
		});
	}

	override async handle(
		req: handler.APIRequest<signupApi.Request>,
		trace: handler.ReqContext,
	): Promise<handler.APIResponse<signupApi.Response>> {

		const result = await db.db.runTransaction<
			signupApi.ResponseProblem | { tag: "ok", ok: { userID: UserID, inviterID: UserID } }
		>(async transaction => {
			const invitationReference = db.invitationPath(req.request.invitationCode);

			// Check that the invitation can still be used.
			const invitation = await transaction.get(invitationReference);
			const expires = handler.asTimestamp(invitation.get("expires"));
			const remainingUses = handler.asNumber(invitation.get("remainingUses"));
			if (expires === null || expires.getTime() < Date.now()
				|| remainingUses === null || remainingUses <= 0) {
				return {
					tag: "problem",
					badCode: "not-found",
				};
			}

			// Check that there isn't another user already
			const existingWithUsername = await transaction.get(
				db.userByLoginUsername(req.request.login.username)
			);
			if (existingWithUsername.docs.length !== 0) {
				return {
					tag: "problem",
					badUsername: "unavailable",
				};
			}

			// Verify that the public key works and the client was able to
			// generate a signature.
			try {
				const publicKey = await crypto.subtle.importKey(
					"jwk",
					req.request.login.keyCredential.keyPair.publicKeyJwt as crypto.JsonWebKey,
					req.request.login.keyCredential.keyPair.algorithmParameters,
					false,
					["verify"],
				);

				const verified = await crypto.subtle.verify(
					req.request.login.keyCredential.keyPair.signatureParameters,
					publicKey,
					req.request.login.keyCredentialUsernameChallenge,
					new TextEncoder().encode(req.request.login.username),
				);
				if (!verified) {
					throw new handler.APIError("invalid keyCredentialUsernameChallenge", 400);
				}
			} catch (e) {
				console.error("verifying challenge failed:", e);
				throw new handler.APIError("invalid key credential", 400);
			}

			// Mark the invitation code as used
			transaction.update(invitationReference, {
				remainingUses: FieldValue.increment(-1),
			});

			// Create the user object
			const userID: UserID = ulid() as UserID;
			const inviterID = invitation.get("inviter") as UserID;
			transaction.create(db.userPath(userID), v.toPlainJSON({
				login: {
					username: req.request.login.username.toLowerCase(),
					keyCredential: req.request.login.keyCredential,
				},
				inviterID,
				debugPermission: false,
			} satisfies db.User));

			transaction.create(db.userForFriendsPath(userID), {
				displayName: req.request.displayName,
			} satisfies db.UserForFriends);

			return { tag: "ok", ok: { userID, inviterID } };
		});

		if (result.tag === "problem") {
			return { body: result };
		}
		const { userID, inviterID } = result.ok;

		const inviterFriend = await db.userForFriendsPath(inviterID).get();
		const inviterDisplayName = handler.asString(inviterFriend.get("displayName"));

		trace.includeServerTiming ||= v.booleans
			.optional()
			.defaulting(false)
			.validate(inviterFriend.get("debugPermission"), []);

		return {
			body: {
				tag: "created",
				userID,
				inviter: {
					userID: inviterID,
					displayName: inviterDisplayName || undefined,
				},
			},
		};
	}

	static async inject(): Promise<Handler> {
		return new Handler();
	}
}
