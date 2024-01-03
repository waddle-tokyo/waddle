export type Request = {
	username: string,

	/**
	 * A challenge ID that was created using the makeLoginChallenge API
	 * for this `loginID`.
	 */
	loginChallenge: string,

	/**
	 * A signature of the `challengeID` that will be verified with the
	 * login ECDSA public key that is registered with this user.
	 */
	loginECDSASignature: Uint8Array,
};

export type ResponseFailure = {
	tag: "failure",
	reason: "challenge" | "credentials-username" | "credentials-signature",
};

export type ResponseSuccess = {
	tag: "success",
	firebaseToken: string,
};

export type Response = ResponseFailure | ResponseSuccess;
