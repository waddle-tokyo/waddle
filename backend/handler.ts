import * as http from "node:http";

import { Timestamp } from "firebase-admin/firestore";

import * as v from "../apis/validator.js";

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

export type APIHandler<Req, Resp extends v.Serializable> =
	(req: APIRequest<Req>) => Promise<APIResponse<Resp>>;

export type APIRequest<Req> = {
	request: Req,
};

export type APIResponse<Resp extends v.Serializable> = {
	body: Resp,
	headers?: Record<string, string>,
};

export function useHandler<Req, Resp extends v.Serializable>(
	validator: v.Validator<Req>,
	handler: APIHandler<Req, Resp>
): (incoming: http.IncomingMessage, response: http.ServerResponse) => void {
	return async (incoming: http.IncomingMessage, response: http.ServerResponse) => {
		const bodyText = await getBodyText(incoming, {
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

			const responseObject = await handler({
				request: validatedObject,
			});

			response.writeHead(200, {
				"Content-Type": "application/json",
				...responseObject.headers,
			});
			response.end(v.serialize(responseObject.body));
		} catch (e: unknown) {
			if (e instanceof APIError) {
				response.writeHead(e.status, {
					"Content-Type": "application/json",
				});
				response.end(v.serialize({
					message: e.message,
					path: e.path,
				}));
			} else {
				console.error(e);
				response.writeHead(500, {
					"Content-Type": "application/json",
				});
				response.end(v.serialize({
					message: "internal server error",
				}));
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
