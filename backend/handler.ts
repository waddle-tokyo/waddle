import * as http from "node:http";

import { Timestamp } from "firebase-admin/firestore";
import { ulid } from "ulid";

import * as v from "../apis/validator.js";

export class ReqContext {
	public readonly trace: string;
	private handlerPath: string = "(redacted)";
	public includeServerTiming: boolean = false;
	private serverTimings: string[] = [];

	constructor(
		public incoming: http.IncomingMessage,
		public response: http.ServerResponse,
	) {
		this.trace = ulid().toLowerCase();
	}

	prefix(): string {
		return `${new Date().toISOString()} ${this.trace}:`;
	}

	log(...messages: string[]): void {
		console.log(this.prefix() + "\t" + messages.join("\t"));
	}

	recordTime(name: string, millis: number) {
		if (/^[a-zA-Z0-9]+$/.test(name)) {
			throw new Error("illegal metric name");
		}

		this.serverTimings.push(`${name},dur=${millis.toFixed(1)}`);
		this.log(name, "took", millis.toFixed(1), "ms");
	}

	serverTimingHeaders(): Record<string, string> {
		if (this.includeServerTiming) {
			return {
				"server-timing": this.serverTimings.join(", "),
			};
		}
		return {};
	}

	async measureTime<T>(name: string, work: () => Promise<T>): Promise<T> {
		const before = performance.now();
		try {
			return await work();
		} finally {
			const after = performance.now();
			this.recordTime(name, after - before);
		}
	}

	setHandler(handlerPath: string): void {
		this.handlerPath = handlerPath;
		this.log("handling", handlerPath);
	}

	endWithEmpty(status: number, headers: Record<string, string>): void {
		this.log(
			"responding ",
			status.toFixed(0),
			"empty",
			this.incoming.method || "?",
			this.handlerPath,
		);

		this.response.writeHead(status, {
			...this.serverTimingHeaders(),
			...headers,
		});
		this.response.end();
	}

	endWith(
		status: number,
		headers: Record<string, string>,
		response: v.Serializable
	): void {
		const serialized = v.serialize(response);

		this.log(
			"responding ",
			status.toFixed(0),
			"length",
			serialized.length.toFixed(0),
			"C",
			this.incoming.method || "?",
			this.handlerPath,
		);

		this.response.writeHead(status, {
			...this.serverTimingHeaders(),
			...headers,
			"content-type": "application/json",
			"content-length": new TextEncoder().encode(serialized).length,
		});
		this.response.end(serialized);
	}
}

export class APIError extends Error {
	constructor(
		public message: string,
		public status: number,
		public path?: string[],
	) {
		super();
	}
}

export const timestamps = new class TimestampValidator extends v.Validator<Timestamp> {
	validate(value: unknown, path: string[]): Timestamp {
		if (value instanceof Timestamp) {
			return value;
		}
		throw new v.ValidationError(path, "must be a Firestore Timestamp");
	}
};

export type APIRequest<Req> = {
	request: Req,
};

export type APIResponse<Resp extends v.Serializable> = {
	body: Resp,
	headers?: Record<string, string>,
};

export abstract class Handler<Req, Resp extends v.Serializable> {
	abstract validator(): v.Validator<Req>;

	abstract handle(req: APIRequest<Req>, trace: ReqContext): Promise<APIResponse<Resp>>;
}

export function useHandler<Req, Resp extends v.Serializable>(
	handler: Handler<Req, Resp>,
): (trace: ReqContext) => void {
	const validator = handler.validator();
	return async (trace: ReqContext) => {
		const bodyText = await getBodyText(trace.incoming, {
			maxLengthBytes: 1024 * 1024,
			maxTimeMillis: 2_000,
		});

		try {
			let bodyObject: unknown;
			try {
				bodyObject = JSON.parse(bodyText);
			} catch (e) {
				console.error("request JSON parsing failed:", e);
				throw new APIError("bad JSON syntax", 400);
			}

			let validatedObject: Req;
			try {
				validatedObject = validator.validate(bodyObject, []);
			} catch (e) {
				if (e instanceof v.ValidationError) {
					const location = e.path.length === 0
						? "<root>"
						: e.path.join(".");
					throw new APIError(`${location}: ${e.message}`, 400, e.path);
				}
				throw e;
			}

			const responseObject = await handler.handle({
				request: validatedObject,
			}, trace);

			trace.endWith(200, responseObject.headers || {}, responseObject.body);
		} catch (e: unknown) {
			if (e instanceof APIError) {
				trace.endWith(e.status, {}, {
					message: e.message,
					path: e.path,
				});
			} else {
				console.error(e);
				trace.endWith(500, {}, {
					code: 500,
					message: "internal server error",
				});
			}
		}
	};
}

function getBodyText(
	incoming: http.IncomingMessage,
	options: { maxTimeMillis: number, maxLengthBytes: number },
): Promise<string> {
	return new Promise((resolve, reject) => {
		const chunks: Uint8Array[] = [];
		let length = 0;
		incoming.on("data", (chunk: Buffer) => {
			chunks.push(chunk);
			length += chunk.length;
			if (length > options.maxLengthBytes) {
				reject(new APIError("max body size exceeded", 400));
			}
		});
		incoming.on("end", () => {
			resolve(Buffer.concat(chunks).toString());
		});
		setTimeout(() => {
			reject(new APIError("max request time exceeded", 400));
		}, options.maxTimeMillis);
	});
}

export function asTimestamp(at: unknown): Date | null {
	if (at instanceof Timestamp) {
		return at.toDate();
	} if (typeof at !== "string" || !v.timestampRegex.test(at)) {
		return null;
	}
	return new Date(at);
}

export function asNumber(n: unknown): number | null {
	if (typeof n === "number" && n === n) {
		return n;
	}
	return null;
}

export function asString(n: unknown): string | null {
	if (typeof n === "string") {
		return n;
	}
	return null;
}
