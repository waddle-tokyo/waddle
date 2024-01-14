import * as http from "node:http";
import * as https from "node:https";

import * as v from "../apis/validator.js";
import * as configuration from "./configuration.js";
import * as handler from "./handler.js";
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
		if (this.allowedCorsOrigins.has(origin)) {
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
		private webConfig: configuration.Config["web"]
	) {
		this.corsHandler = new CORSHandler(webConfig);
	}

	handle(
		incoming: http.IncomingMessage,
		response: http.ServerResponse,
	) {
		const trace = new handler.ReqContext(incoming, response);

		if (!ANY_ORIGIN_ALLOWED.has(trace.incoming.url || "") && this.corsHandler.handle(trace)) {
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

	async serveHttps(
		port: number,
	): Promise<void> {
		const certificateJson = JSON.parse(
			new TextDecoder().decode(
				await secrets.secretsClient.fetchSecret(this.webConfig.certificateSecretId)
			)
		);

		const httpsServerOptions = {
			cert: Buffer.from(new TextEncoder().encode(certificateJson.fullchain)),
			key: Buffer.from(new TextEncoder().encode(certificateJson.privkey)),
		};

		const server = https.createServer(httpsServerOptions, (a, b) => this.handle(a, b));
		server.listen(port);
		console.log("serving HTTPS on port", port);
	}
}

export async function endpoints(config: configuration.Config): Promise<
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
		await implAuthLoginChallenge.Handler.inject({ config }),
	);
	endpoints.set(
		{ method: "POST", path: "/auth/login" },
		await implAuthLogin.Handler.inject({ config }),
	);

	return endpoints;
}