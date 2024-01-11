import { Timestamp, UserID } from "./defs";

export type HexBytes = string & { __brand: "HexBytes" };

const HEX_ALPHABET = "0123456789abcdef";

export const HEX_BYTES_REGEX = new RegExp("^([" + HEX_ALPHABET + "]{2})*$");

export function toHexadecimal(array: Uint8Array): HexBytes {
	let out = "";
	for (const n of array) {
		const low = n % 16;
		const high = (n - low) / 16;
		out += HEX_ALPHABET[low] + HEX_ALPHABET[high];
	}
	return out as HexBytes;
}

export function fromHexadecimal(hex: string): Uint8Array {
	if (!HEX_BYTES_REGEX.test(hex)) {
		throw new Error("invalid format for hex string");
	}

	const out = new Uint8Array(hex.length / 2);
	for (let i = 0; i < hex.length; i += 2) {
		const low = hex[i];
		const high = hex[i + 1];

		const n = HEX_ALPHABET.indexOf(low) + HEX_ALPHABET.indexOf(high) * 16;
		out[i / 2] = n;
	}
	return out;
}


export abstract class Validator<T> {
	/**
	 * @throws `ValidationError`
	 */
	abstract validate(value: unknown, path: string[]): T;

	refine(
		predicate: (t: T) => boolean,
		invalidMessage?: string
	): Validator<T> {
		return new Refinement(this, predicate, invalidMessage);
	}

	optional(): Validator<T | undefined> {
		return optional(this);
	}

	map<B>(f: (t: T) => B): Validator<B> {
		return new Mapper(this, f);
	}

	defaulting(defaultValue: NonNullable<T>): Validator<NonNullable<T>> {
		return this.map(value => {
			if (value === undefined || value === null) {
				return defaultValue;
			}
			return value;
		});
	}
}

export class ValidationError {
	path: string[];
	constructor(path: string[], public message: string) {
		this.path = [...path];
	}
}

export class Mapper<A, B> extends Validator<B> {
	constructor(
		private validator: Validator<A>, private f: (a: A) => B
	) { super(); }

	validate(value: unknown, path: string[]): B {
		const a = this.validator.validate(value, path);
		return this.f(a);
	}
}

export class Strings extends Validator<string> {
	validate(value: unknown, path: string[]): string {
		if (typeof value === "string") {
			return value;
		}
		throw new ValidationError(path, "must be a string");
	}

	regex(regex: RegExp, invalidMessage?: string) {
		return this.refine(x => regex.test(x), invalidMessage);
	}
}

export const strings = new Strings();

export class Booleans extends Validator<boolean> {
	validate(value: unknown, path: string[]): boolean {
		if (typeof value === "boolean") {
			return value;
		}
		throw new ValidationError(path, "must be a boolean");
	}
}

export const booleans = new Booleans();

export class Numbers extends Validator<number> {
	validate(value: unknown, path: string[]): number {
		if (typeof value === "number") {
			if (value !== value || !isFinite(value)) {
				throw new ValidationError(path, "must be a finite number");
			}
			return value;
		}
		throw new ValidationError(path, "must be a number");
	}
}

export const numbers = new Numbers();

export class Arrays<T> extends Validator<readonly T[]> {
	constructor(private elements: Validator<T>) {
		super();
	}

	validate(value: unknown, path: string[]): readonly T[] {
		if (!Array.isArray(value)) {
			throw new ValidationError(path, "must be an array");
		}
		const out: T[] = [];
		for (let i = 0; i < value.length; i++) {
			try {
				path.push(i.toFixed(0));
				out.push(this.elements.validate(value[i], path));
			} finally {
				path.pop();
			}
		}
		return Object.freeze(out);
	}
}

/**
 * Absent and undefined values are treated the same.
 *
 * Extra fields are silently dropped.
 */
export class Records<R extends object> extends Validator<R> {
	constructor(private record: { [K in keyof R]: Validator<R[K]> }) {
		super();
	}

	validate(object: unknown, path: string[]): R {
		if (object === null || typeof object !== "object") {
			throw new ValidationError(path, "must be an object");
		}

		const out: any = {};
		for (const [key, keyValidator] of Object.entries(this.record)) {
			const value = (object as any)[key];
			try {
				path.push(key);
				const validatedValue = (keyValidator as Validator<unknown>).validate(value, path);
				out[key] = validatedValue;
			} finally {
				path.pop();
			}
		}
		return Object.freeze(out);
	}
}

export class Union<U> extends Validator<U> {
	private alternatives: Validator<U>[];
	constructor(...alternatives: Validator<U>[]) {
		if (alternatives.length < 2) {
			throw new Error("must provide at least two alternatives");
		}
		super();
		this.alternatives = alternatives;
	}

	validate(value: unknown, path: string[]): U {
		let problems: ValidationError[] = [];
		for (const alternative of this.alternatives) {
			try {
				return alternative.validate(value, path);
			} catch (e) {
				if (e instanceof ValidationError) {
					problems.push(e);
				} else {
					throw e;
				}
			}
		}

		const common = commonPrefix(problems.map(problem => problem.path));

		const message = problems.map(problem => {
			const pathSuffix = problem.path.slice(common.length).join(".");
			return pathSuffix + ": " + problem.message
		}).join(" OR ");

		throw new ValidationError(common, message);
	}
}

function commonPrefix<T>(arrays: T[][]): T[] {
	const prefix = [...arrays[0]];
	for (let i = 1; i < arrays.length; i++) {
		const array = arrays[i];
		for (let k = 0; k < array.length && k < prefix.length; k++) {
			if (array[k] !== prefix[k]) {
				prefix.splice(k);
			}
		}
	}
	return prefix;
}

export class Optional<T> extends Validator<T | undefined> {
	constructor(private sub: Validator<T>) {
		super();
	}

	validate(value: unknown, path: string[]): T | undefined {
		if (value === undefined) {
			return value;
		}
		return this.sub.validate(value, path);
	}
}

export class AnyObject extends Validator<Serializable & object> {
	validate(value: unknown, path: string[]): Serializable & object {
		if (value !== null && typeof value === "object") {
			return JSON.parse(JSON.stringify(value)) as Serializable & object;
		}
		throw new ValidationError(path, "must be any object");
	}
}

export class LiteralString<L extends string> extends Validator<L> {
	constructor(private literal: L) {
		super();
	}

	validate(value: unknown, path: string[]): L {
		if (value === this.literal) {
			return this.literal;
		}
		throw new ValidationError(
			path,
			"must be literal " + serialize(this.literal),
		);
	}
}

export class LiteralNumber<L extends number> extends Validator<L> {
	constructor(private literal: L) {
		super();
	}

	validate(value: unknown, path: string[]): L {
		if (value === this.literal) {
			return this.literal;
		}
		throw new ValidationError(
			path,
			"must be literal " + serialize(this.literal),
		);
	}
}

export class Refinement<T> extends Validator<T> {
	constructor(
		private sub: Validator<T>,
		private predicate: (t: T) => boolean,
		private invalidMessage?: string,
	) {
		super();
	}

	validate(value: unknown, path: string[]): T {
		const typed = this.sub.validate(value, path);
		if (!this.predicate(typed)) {
			throw new ValidationError(path, this.invalidMessage || "invalid");
		}
		return typed;
	}
}

export function optional<T>(t: Validator<T>) {
	return new Optional(t);
}

export function array<T>(t: Validator<T>) {
	return new Arrays(t);
}

export const timestampRegex = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[0-9]{2}|[0-9]{2}:?[0-9]{2})$/;

export const timestamp: Validator<Timestamp> =
	strings.regex(timestampRegex, "invalid timestamp") as Validator<Timestamp>;

export const hexBytes: Validator<Uint8Array> = strings.regex(HEX_BYTES_REGEX).map(fromHexadecimal);

export const userID = strings.regex(/^[A-Z0-9]+$/, "invalid UserID") as Validator<UserID>;

export type Serializable =
	string | number | Date | Uint8Array | undefined
	| Serializable[]
	| { [field: string]: Serializable };

export function serialize(x: Serializable): string {
	return JSON.stringify(x, (_, value) => {
		if (value instanceof Uint8Array) {
			return toHexadecimal(value);
		} else if (value instanceof Date) {
			return value.toISOString();
		} else if (value instanceof Function) {
			throw new Error("functions are not serializable");
		}
		return value;
	});
}
