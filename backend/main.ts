import * as http from "node:http";
import * as https from "node:https";

import * as gcloudDns from "@google-cloud/dns";

import { AnonDiscovery, anonDiscoveryPath } from "./db.js";
import * as handler from "./handler.js";
import * as implAuthLogin from "./impl/auth/login.js";
import * as implAuthLoginChallenge from "./impl/auth/loginChallenge.js";
import * as implAuthSignup from "./impl/auth/signup.js";
import * as secrets from "./secrets.js";
import * as v from "../apis/validator.js";

import { config } from "./config.js";

const ALLOWED_CORS_ORIGINS = new Set(config.web.allowedCorsOrigins);

function handleCORS(
	incoming: http.IncomingMessage,
	response: http.ServerResponse,
): boolean {
	const origin = incoming.headers.origin || "";
	if (ALLOWED_CORS_ORIGINS.has(origin)) {
		response.setHeader("access-control-allow-origin", origin);
		response.setHeader("access-control-allow-methods", "POST, GET, OPTIONS, DELETE");
		response.setHeader("access-control-max-age", "86400");
		response.setHeader("access-control-allow-headers", "Cookie, Content-Type");
		response.setHeader("access-control-allow-credentials", "true");

		if (incoming.method === "OPTIONS") {
			response.writeHead(204);
			response.end();
			return true;
		}
		return false;
	}

	response.writeHead(403);
	const message = {
		code: 403,
		reason: "Origin is not allowed.",
		origin,
		allowedOrigins: [...ALLOWED_CORS_ORIGINS],
	};
	response.end(JSON.stringify(message));
	return true;
}

function requestListener(
	incoming: http.IncomingMessage,
	response: http.ServerResponse,
): void {
	console.log("request:", incoming.method || "???", (incoming.url || "").substring(0, 120));

	if (handleCORS(incoming, response)) {
		return;
	}

	if (incoming.url === "/health") {
		const message = {
			status: "healthy",
		};
		const string = v.serialize(message);
		response.writeHead(200, { "content-length": string.length });
		response.end(string);
		return;
	} else if (!incoming.url) {
		response.writeHead(405);
		response.end();
		return;
	} else if (incoming.url === "/auth/signup" && incoming.method === "POST") {
		const h = handler.useHandler(implAuthSignup.requestValidator, implAuthSignup.handler);
		return h(incoming, response);
	} else if (incoming.url === "/auth/login-challenge" && incoming.method === "POST") {
		const h = handler.useHandler(implAuthLoginChallenge.requestValidator, implAuthLoginChallenge.handler);
		return h(incoming, response);
	} else if (incoming.url === "/auth/login" && incoming.method === "POST") {
		const h = handler.useHandler(implAuthLogin.requestValidator, implAuthLogin.handler);
		return h(incoming, response);
	}

	response.writeHead(404);
	response.end("no handler for " + incoming.method + " " + incoming.url);
}

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
		private externalIP: string,
	) {
		this.name = "h" + this.externalIP.split(".").map(x => x.padStart(3, "0")).join("");
	}

	getDomain(): string {
		return this.name + config.web.apiDomain;
	}

	async setup() {
		const dnsClient = new gcloudDns.DNS();
		const zone = dnsClient.zone(config.web.dns.zoneName);
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
	console.log("main");

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

	const discoveryPublisher = new DiscoveryPublisher(externalIP);
	await discoveryPublisher.setup();
	await discoveryPublisher.autoRefreshDiscovery();

	const certificateJson = JSON.parse(
		new TextDecoder().decode(
			await secrets.secretsClient.fetchSecret(config.web.certificateSecretId)
		)
	);

	const httpsServerOptions = {
		cert: Buffer.from(new TextEncoder().encode(certificateJson.fullchain)),
		key: Buffer.from(new TextEncoder().encode(certificateJson.privkey)),
	};

	const server = https.createServer(httpsServerOptions, requestListener);
	const PORT = 443;
	server.listen(PORT);
	console.log("serving HTTPS on port", PORT);
}

main();
