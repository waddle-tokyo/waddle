import { getAuth, signInWithCustomToken } from "firebase/auth";

import * as loginApi from "../../../apis/auth/login.ts";
import * as loginChallengeApi from "../../../apis/auth/loginChallenge.ts";
import * as v from "../../../apis/validator.ts";
import { getTagById } from "../common.ts";
import { discovery } from "../firebase.ts";

const usernameInput = getTagById("input-username", "input");
const passwordInput = getTagById("input-password", "input");
const loginButton = getTagById("button-login", "button");
const submitResultMessage = getTagById("submit-result", "section");

async function loginAttempt(): Promise<{ tag: "error" | "success", message: string }> {
	// Fetch the challenge and keys
	const loginChallengeRequest: loginChallengeApi.Request = {
		username: usernameInput.value,
	};

	submitResultMessage.style.display = "none";
	submitResultMessage.className = "";

	const challenge = await discovery.post("/auth/login-challenge", loginChallengeRequest);
	if (challenge.status >= 400) {
		return {
			tag: "error",
			message: "There was an unexpected issue starting a login.",
		};
	}

	const loginChallengeResponse = vLoginChallengeResponse.validate(challenge.body, []);
	if (loginChallengeResponse.tag === "failure") {
		if (loginChallengeResponse.reason === "credentials-username") {
			return {
				tag: "error",
				message: `There is no account with the username '${usernameInput.value}'.`,
			};
		}

		return {
			tag: "error",
			message: "There was an unknown problem starting a login attempt.",
		};
	}

	const passwordAsKey = await window.crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(passwordInput.value),
		"PBKDF2",
		false,
		["deriveKey"],
	);

	const passwordBasedEncryptionKey = await window.crypto.subtle.deriveKey(
		loginChallengeResponse.keyCredential.pbkdf2Params,
		passwordAsKey,
		{
			name: "AES-GCM",
			length: 256,
		},
		false,
		["encrypt", "decrypt", "wrapKey", "unwrapKey"],
	);

	const privateKey = await crypto.subtle.unwrapKey(
		"jwk",
		loginChallengeResponse.keyCredential.keyPair.privateKey.encryptedBlob,
		passwordBasedEncryptionKey,
		loginChallengeResponse.keyCredential.keyPair.privateKey.encryptionParameters satisfies AesGcmParams,
		loginChallengeResponse.keyCredential.keyPair.algorithmParameters,
		true,
		["sign"],
	);

	const signature = await crypto.subtle.sign(
		loginChallengeResponse.keyCredential.keyPair.signatureParameters,
		privateKey,
		new TextEncoder().encode(loginChallengeResponse.loginChallenge),
	);

	const loginRequest: loginApi.Request = {
		username: usernameInput.value,
		loginChallenge: loginChallengeResponse.loginChallenge,
		loginECDSASignature: new Uint8Array(signature),
	};

	const loginResponseWrapped = await discovery.post("/auth/login", loginRequest);
	if (loginResponseWrapped.status >= 400) {
		console.error(loginResponseWrapped);
		return {
			tag: "error",
			message: "There was an unexpected problem trying to log in.",
		};
	}

	const loginResponse = vLoginResponse.validate(loginResponseWrapped.body, []);
	if (loginResponse.tag === "failure") {
		return {
			tag: "error",
			message: `Login rejected: ${loginResponse.reason}`,
		};
	}

	const userCredential = await signInWithCustomToken(
		getAuth(),
		loginResponse.firebaseToken,
	);
	console.log(userCredential);

	return {
		tag: "success",
		message: "Log in completed.",
	};
}

loginButton.addEventListener("click", async () => {
	// Disable the form while sending the request
	usernameInput.disabled = true;
	passwordInput.disabled = true;
	loginButton.disabled = true;

	// Normalize the input
	usernameInput.value = usernameInput.value.toLocaleLowerCase();

	const result = await loginAttempt();

	// Re-enable the form and render the output
	usernameInput.disabled = false;
	passwordInput.disabled = false;
	loginButton.disabled = false;

	submitResultMessage.className = result.tag;
	submitResultMessage.textContent = result.message;
	submitResultMessage.style.display = "block";
});

loginButton.disabled = false;

const vLoginChallengeResponse = new v.Union<loginChallengeApi.Response>(
	new v.Records<loginChallengeApi.ResponseFailure>({
		tag: new v.LiteralString("failure"),
		reason: new v.LiteralString("credentials-username"),
	}),
	new v.Records<loginChallengeApi.ResponseSuccess>({
		tag: new v.LiteralString("success"),
		loginChallenge: v.strings,
		loginChallengeExpiry: v.timestamp,
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
					encryptionParameters: new v.Records({
						name: new v.LiteralString("AES-GCM"),
						tagLength: new v.LiteralNumber(128),
						iv: v.hexBytes,
					}),
					encryptedBlob: v.hexBytes,
				}),
			}),
		}),
	}),
);

const vLoginResponse = new v.Union<loginApi.Response>(
	new v.Records({
		tag: new v.LiteralString("failure"),
		reason: new v.Union(
			new v.LiteralString("credentials-username"),
			new v.LiteralString("credentials-signature"),
			new v.LiteralString("challenge"),
		),
	}),
	new v.Records({
		tag: new v.LiteralString("success"),
		firebaseToken: v.strings,
	}),
);
