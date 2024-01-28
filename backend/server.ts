import * as http from "node:http";
import * as https from "node:https";
import * as net from "node:net";

import * as v from "../apis/validator.js";
import * as configuration from "./configuration.js";
import * as handler from "./handler.js";
import { LoginChallenges } from "./impl/auth/challenges.js";
import * as implAuthLogin from "./impl/auth/login.js";
import * as implAuthLoginChallenge from "./impl/auth/loginChallenge.js";
import * as implAuthSignup from "./impl/auth/signup.js";
import * as secrets from "./secrets.js";

const ANY_ORIGIN_ALLOWED = new Set([
	"/health",
]);

export class CORSHandler {
	private allowedCorsOrigins: Set<string>;

	constructor(webConfig: configuration.Config["web"]) {
		this.allowedCorsOrigins = new Set(webConfig.allowedCorsOrigins);
	}

	handle(trace: handler.ReqContext): boolean {
		const origin = trace.incoming.headers.origin || "";
		const originIsAllowed = this.allowedCorsOrigins.has(origin);
		const thisEndpointAllowsAnyOrigin = ANY_ORIGIN_ALLOWED.has(trace.incoming.url || "");
		if (originIsAllowed || thisEndpointAllowsAnyOrigin) {
			const response = trace.response;
			response.setHeader("access-control-allow-origin", origin);
			response.setHeader("access-control-allow-methods", "POST, GET, OPTIONS, DELETE");
			response.setHeader("access-control-max-age", "86400");
			response.setHeader("access-control-allow-headers", "Cookie, Content-Type");
			response.setHeader("access-control-allow-credentials", "true");

			if (trace.incoming.method === "OPTIONS") {
				trace.endWithEmpty(204, {});
			}
			return false;
		}

		const message = {
			code: 403,
			reason: "Origin is not allowed.",
			origin,
			allowedOrigins: [...this.allowedCorsOrigins],
		};
		trace.endWith(403, {}, message);

		return true;
	}
}

export class Server {
	private corsHandler: CORSHandler;

	constructor(
		private endpoints: Map<
			{ path: string, method: "POST" },
			handler.Handler<unknown, v.Serializable>
		>,
		private webConfig: configuration.Config["web"],
		private secretsClient: secrets.SecretsClient,
	) {
		this.corsHandler = new CORSHandler(webConfig);
	}

	handle(
		incoming: http.IncomingMessage,
		response: http.ServerResponse,
	) {
		const trace = new handler.ReqContext(incoming, response);

		if (this.corsHandler.handle(trace)) {
			return;
		}

		if (incoming.url === "/health") {
			trace.setHandler("/health");

			const message = {
				status: "healthy",
			};
			trace.endWith(200, {}, message);
			return;
		} else if (!incoming.url) {
			trace.endWith(405, {}, {
				code: 405,
				reason: "Invalid url",
			});
			return;
		}

		for (const [route, endpoint] of this.endpoints) {
			if (incoming.url === route.path && incoming.method === route.method) {
				const h = handler.useHandler(endpoint);
				return h(trace);
			}
		}

		trace.endWith(404, {}, {
			code: 404,
			reason: "no handler for " + incoming.method + " " + incoming.url,
		});
	}

	async serveHttp(): Promise<{ server: http.Server, port: number }> {
		const server = http.createServer({}, (a, b) => this.handle(a, b));
		server.listen();

		const port = (server.address() as net.AddressInfo).port;
		console.log("serving HTTP on port", port);
		return { server, port };
	}

	async serveHttps(
		port: number,
	): Promise<{ server: http.Server, port: number }> {
		const certificateJson = JSON.parse(
			new TextDecoder().decode(
				await this.secretsClient.fetchSecret(this.webConfig.certificateSecretId)
			)
		);

		const httpsServerOptions = {
			cert: Buffer.from(new TextEncoder().encode(certificateJson.fullchain)),
			key: Buffer.from(new TextEncoder().encode(certificateJson.privkey)),
		};

		const server = https.createServer(httpsServerOptions, (a, b) => this.handle(a, b));
		server.listen(port);
		console.log("serving HTTPS on port", port);
		return { server, port };
	}
}

export async function endpoints(
	config: configuration.Config,
	secretsClient: secrets.SecretsClient,
	loginChallenges: LoginChallenges,
): Promise<
	Map<{ path: string, method: "POST" }, handler.Handler<unknown, v.Serializable>>
> {
	const endpoints = new Map<
		{ path: string, method: "POST" },
		handler.Handler<unknown, v.Serializable>
	>();

	endpoints.set(
		{ method: "POST", path: "/auth/signup" },
		await implAuthSignup.Handler.inject(),
	);
	endpoints.set(
		{ method: "POST", path: "/auth/login-challenge" },
		await implAuthLoginChallenge.Handler.inject({ config, loginChallenges }),
	);
	endpoints.set(
		{ method: "POST", path: "/auth/login" },
		await implAuthLogin.Handler.inject({ config, secretsClient }),
	);

	return endpoints;
}
