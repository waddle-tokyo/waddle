import * as fs from "node:fs";

import * as gcloudDns from "@google-cloud/dns";
import * as gcloudSecretManager from "@google-cloud/secret-manager";

import * as configuration from "./configuration.js";
import * as secrets from "./secrets.js";
import * as server from "./server.js";

import { AnonDiscovery, anonDiscoveryPath } from "./db.js";
import { LoginChallenges } from "./impl/auth/challenges.js";

async function retrieveGCPMetadata(path: string) {
	const projectIdResponse = await fetch("http://metadata.google.internal/computeMetadata/" + path, {
		headers: { "Metadata-Flavor": "Google" },
	});
	return await projectIdResponse.text();
}

class DiscoveryPublisher {
	private autoRefreshDiscoveryToken: null | NodeJS.Timeout = null;
	private name: string;
	private expiresMillis = 15 * 60 * 1000;

	constructor(
		private config: configuration.Config,
		private externalIP: string,
	) {
		this.name = "h" + this.externalIP.split(".").map(x => x.padStart(3, "0")).join("");
	}

	getDomain(): string {
		return this.name + this.config.web.apiDomain;
	}

	async setup() {
		const dnsClient = new gcloudDns.DNS();
		const zone = dnsClient.zone(this.config.web.dns.zoneName);
		const aRecords = (await zone.getRecords("A"))[0];
		const desiredSubdomain = this.getDomain() + ".";
		const existingRecord = aRecords.find(record => record.metadata.name === desiredSubdomain);
		if (!existingRecord) {
			// Create a record pointing to me
			const newRecord = zone.record("a", {
				name: desiredSubdomain,
				data: this.externalIP,
				ttl: 500,
			});
			await zone.addRecords(newRecord);
			console.log("creating new DNS record:", newRecord);
		} else {
			console.log("not creating DNS record because one already exists:", existingRecord);
		}
	}

	async autoRefreshDiscovery() {
		if (this.autoRefreshDiscoveryToken !== null) {
			return;
		}
		await this.refreshDiscovery();
		this.autoRefreshDiscoveryToken = setInterval(() => this.refreshDiscovery(), this.expiresMillis / 3.1);
	}

	cancelAutoRefreshDiscovery() {
		if (this.autoRefreshDiscoveryToken !== null) {
			clearInterval(this.autoRefreshDiscoveryToken);
			this.autoRefreshDiscoveryToken = null;
		}
	}

	async refreshDiscovery() {
		return await anonDiscoveryPath(this.name).set({
			type: "api",
			expires: new Date(Date.now() + this.expiresMillis),
			version: "?v2",
			domain: this.getDomain(),
		} satisfies AnonDiscovery);
	}
}

async function main() {
	const CONFIG_FILE = "conf.jsonc";
	const configContents = fs.readFileSync(CONFIG_FILE, "utf-8");
	const config = configuration.fromString(configContents, CONFIG_FILE);

	const projectID = await retrieveGCPMetadata("v1/project/project-id");
	const zoneID = (await retrieveGCPMetadata("v1/instance/zone")).replace(/^.*zones\//g, "");
	const instanceID = await retrieveGCPMetadata("v1/instance/id");
	const instanceName = await retrieveGCPMetadata("v1/instance/name");
	const regionID = zoneID.replace(/-[^-]+$/g, "");
	const externalIP = (await retrieveGCPMetadata("v1/instance/network-interfaces/0/access-configs/0/external-ip")).trim();

	console.log(`projectID(${projectID})`);
	console.log(`zoneID(${zoneID})`);
	console.log(`instanceID(${instanceID})`);
	console.log(`instanceName(${instanceName})`);
	console.log(`regionID(${regionID})`);
	console.log(`externalIP(${externalIP})`);

	const discoveryPublisher = new DiscoveryPublisher(config, externalIP);
	await discoveryPublisher.setup();
	await discoveryPublisher.autoRefreshDiscovery();


	const secretsClient = new secrets.GCPSecretsClient(
		new gcloudSecretManager.SecretManagerServiceClient()
	);

	const loginChallenges = await LoginChallenges.inject({
		secretsClient,
		authConfig: config.auth,
	});

	const endpoints = await server.endpoints(config, secretsClient, loginChallenges);
	const s = new server.Server(endpoints, config.web, secretsClient);
	await s.serveHttps(443);
}

main();
