import * as gcloudSecretManager from "@google-cloud/secret-manager";

export class SecretsClient {
	private secretManagerClient = new gcloudSecretManager.SecretManagerServiceClient();

	async fetchSecret(secretId: string): Promise<Uint8Array> {
		const secretArr = await this.secretManagerClient.accessSecretVersion({
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

export const secretsClient: SecretsClient = new SecretsClient();
