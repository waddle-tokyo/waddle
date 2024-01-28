import * as signupApi from "../../../apis/auth/signup.ts";
import * as v from "../../../apis/validator.ts";
import { getTagById } from "../common.ts";
import { discovery } from "../firebase.ts";

const invitationInput = getTagById("input-invitation", "input");
const usernameInput = getTagById("input-username", "input");
const passwordInput = getTagById("input-password", "input");
const passwordConfirmInput = getTagById("input-passwordconfirm", "input");
const nameInput = getTagById("input-name", "input");
const signupButton = getTagById("button-signup", "button");

const submitResultMessage = getTagById("submit-result", "section");

function updateConfirmPasswordValidity() {
	if (passwordConfirmInput.value.length === 0 || passwordInput.value === passwordConfirmInput.value) {
		passwordConfirmInput.setCustomValidity("");
	} else {
		passwordConfirmInput.setCustomValidity("Passwords do not match.");
	}

	// TODO: Compute some minimum password quality.
}

passwordInput.addEventListener("input", updateConfirmPasswordValidity);
passwordConfirmInput.addEventListener("input", updateConfirmPasswordValidity);

function updateSubmitStatus() {
	let valid = true;
	if (!invitationInput.validity.valid) {
		valid = false;
	}
	if (!usernameInput.validity.valid) {
		valid = false;
	}
	if (!passwordInput.validity.valid) {
		valid = false;
	}
	if (!passwordConfirmInput.validity.valid) {
		valid = false;
	}
	if (!nameInput.validity.valid) {
		valid = false;
	}

	// Reduce opacity to indicate that the message is stale.
	submitResultMessage.style.opacity = "60%";

	signupButton.disabled = !valid;
}

invitationInput.addEventListener("input", updateSubmitStatus);
usernameInput.addEventListener("input", updateSubmitStatus);
passwordInput.addEventListener("input", updateSubmitStatus);
passwordConfirmInput.addEventListener("input", updateSubmitStatus);
nameInput.addEventListener("input", updateSubmitStatus);

const queryParameters = new URLSearchParams(window.location.search);
invitationInput.value = queryParameters.get("code") || "";
invitationInput.disabled = false;

signupButton.addEventListener("click", async () => {
	// Disable the form while sending the request
	invitationInput.disabled = true;
	usernameInput.disabled = true;
	passwordInput.disabled = true;
	passwordConfirmInput.disabled = true;
	nameInput.disabled = true;
	signupButton.disabled = true;

	// Normalize the input
	nameInput.value = nameInput.value.trim();
	invitationInput.value = invitationInput.value.toUpperCase();
	usernameInput.value = usernameInput.value.toLocaleLowerCase();

	// Generate a key-pair using the password.
	const passwordSalt = window.crypto.getRandomValues(new Uint8Array(16));
	const passwordAsKey = await window.crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(passwordInput.value),
		"PBKDF2",
		false,
		["deriveKey"],
	);

	const passwordHashParams = {
		name: "PBKDF2" as const,
		hash: "SHA-512" as const,
		salt: passwordSalt,
		// Roughly 4x OWASP recommendation for 2023:
		iterations: 800_000,
	};

	const passwordBasedEncryptionKey = await window.crypto.subtle.deriveKey(
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

	const loginVerifyingKeyPair = await window.crypto.subtle.generateKey(
		signatureAlgorithmParameters,
		true,
		["sign", "verify"],
	);

	const publicKeyJson = await window.crypto.subtle.exportKey("jwk", loginVerifyingKeyPair.publicKey);
	const wrappingIv = await window.crypto.getRandomValues(new Uint8Array(12));
	const privateKeyEncryptionParameters = {
		name: "AES-GCM",
		iv: wrappingIv,
		tagLength: 128,
	} as const;
	const encryptedPrivateKey = new Uint8Array(
		await window.crypto.subtle.wrapKey(
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

	const usernameBytes = new TextEncoder().encode(usernameInput.value);

	const signedUsernameChallenge = new Uint8Array(
		await window.crypto.subtle.sign(
			signatureParameters,
			loginVerifyingKeyPair.privateKey,
			usernameBytes,
		)
	);

	const signupRequest: signupApi.Request = {
		invitationCode: invitationInput.value,
		displayName: nameInput.value,
		login: {
			username: usernameInput.value,
			keyCredential: {
				pbkdf2Params: {
					...passwordHashParams,
					salt: passwordHashParams.salt,
				},
				keyPair: {
					algorithmParameters: signatureAlgorithmParameters,
					signatureParameters,
					privateKey: {
						encryptionParameters: {
							name: privateKeyEncryptionParameters.name,
							tagLength: privateKeyEncryptionParameters.tagLength,
							iv: privateKeyEncryptionParameters.iv,
						},
						encryptedBlob: encryptedPrivateKey,
					},
					publicKeyJwt: publicKeyJson as v.Serializable & object,
				},
			},
			keyCredentialUsernameChallenge: signedUsernameChallenge,
		},
	};

	const result = await discovery.post("/auth/signup", signupRequest);

	submitResultMessage.style.display = "block";
	submitResultMessage.style.opacity = "100%";

	if (result.status >= 400) {
		submitResultMessage.className = "error";
		submitResultMessage.textContent = "There was an unexpected problem with your sign up request.";
	} else {
		const body = vSignupResponse.validate(result.body, []);
		console.log(body);
		if (body.tag === "created") {
			submitResultMessage.className = "success";
			submitResultMessage.textContent = "Your account has been created. Welcome!";
			if (body.inviter.displayName) {
				submitResultMessage.textContent += " We'll let " + body.inviter.displayName + " know you joined.";
			}
			return;
		} else {
			submitResultMessage.className = "error";
			if (body.badCode) {
				submitResultMessage.textContent = "That invitation code didn't work.";
			} else if (body.badUsername) {
				submitResultMessage.textContent = "That login ID is not available.";
			} else {
				submitResultMessage.textContent = "Something was wrong with your input. Try refreshing the page.";
			}
		}
	}

	// Enable the input form so they can try again.
	invitationInput.disabled = false;
	usernameInput.disabled = false;
	passwordInput.disabled = false;
	passwordConfirmInput.disabled = false;
	nameInput.disabled = false;
	signupButton.disabled = false;
});

const vSignupResponse: v.Validator<signupApi.Response> = new v.Union<signupApi.Response>(
	new v.Records<signupApi.ResponseSuccess>({
		tag: new v.LiteralString("created"),
		userID: v.userID,
		inviter: new v.Records({
			userID: v.userID,
			displayName: v.strings.optional(),
		}),
	}),
	new v.Records<signupApi.ResponseProblem>({
		tag: new v.LiteralString("problem"),
		badCode: v.strings.optional(),
		badUsername: v.strings.optional(),
	}),
);
