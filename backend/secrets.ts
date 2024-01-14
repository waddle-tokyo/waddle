import * as gcloudSecretManager from "@google-cloud/secret-manager";

export interface SecretsClient {
	fetchSecret(secretId: string): Promise<Uint8Array>;
}

export class GCPSecretsClient {
	constructor(
		private manager: gcloudSecretManager.SecretManagerServiceClient,
	) { }
	async fetchSecret(secretId: string): Promise<Uint8Array> {
		const secretArr = await this.manager.accessSecretVersion({
			name: secretId + "/versions/latest",
		});

		const secret = secretArr[0].payload;
		if (!secret || !secret.data) {
			throw new Error(`secretId(${secretId}) was not found`);
		}

		const data = secret.data;
		if (typeof data === "string") {
			return new TextEncoder().encode(data);
		}
		return data;
	}
}
