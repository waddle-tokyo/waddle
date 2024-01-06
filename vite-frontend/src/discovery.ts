import * as firebaseApp from "firebase/app";
import * as firestore from "firebase/firestore";
import { Serializable, serialize } from "../../apis/validator";

export class DiscoveryClient {
	private db: Promise<firestore.Firestore>;
	private domains: Set<string> = new Set();
	private lastRefresh = 0;

	constructor(
		private serverType: string,
		firebaseApp: Promise<firebaseApp.FirebaseApp>,
	) {
		this.db = new Promise(resolve => {
			firebaseApp.then(app => resolve(firestore.getFirestore(app)));
		});
	}

	async refreshList(): Promise<void> {
		if (this.lastRefresh > Date.now() - 1000 * 10) {
			return;
		}
		this.lastRefresh = Date.now();

		const query = firestore.query(
			firestore.collection(await this.db, "anon-discovery/"),
			firestore.and(
				firestore.where("type", "==", this.serverType),
				firestore.where("expires", ">", new Date()),
			),
		);

		const active = await firestore.getDocs(query);

		const current = [...this.domains];
		const activeDomains = active.docs
			.map(doc => doc.get("domain") as string)
			.filter(x => typeof x === "string" && x);

		const debugging = [
			"DiscoveryClient.refreshList:",
			"\tcurrent list:",
			...[...current].map(domain => `\t\t${domain}`),
			"",
			"\tfetched list:",
			...[...activeDomains].map(domain => `\t\t${domain}`),
		];
		console.info(debugging.join("\n"));

		// Remove bad hosts asynchronously
		this.checkAllHealth(current);

		await this.checkAllHealth(activeDomains);
	}

	async checkAllHealth(domains: string[]) {
		const healthChecks = domains.map(async domain => {
			try {
				const response = await fetch(`https://${domain}/health`);
				if (response.status >= 400) {
					throw new Error(`${domain} is not currently available`);
				}
				this.domains.add(domain);
			} catch (e) {
				console.info("checking health failed:", e);
				this.markDomainHealth(domain, "unhealthy");
				throw e;
			}
		});
		await Promise.any(healthChecks);
	}

	async chooseDomain(): Promise<string> {
		if (this.domains.size === 0) {
			await this.refreshList();
		}
		for (const domain of this.domains) {
			return domain;
		}
		throw new Error(`no available ${this.serverType} hosts`);
	}

	markDomainHealth(domain: string, health: "healthy" | "unhealthy"): void {
		if (health === "unhealthy") {
			this.domains.delete(domain);
		}
		console.debug(this.serverType, domain, "is", health);
	}

	async post(
		path: string,
		requestBody: Serializable,
		options?: { retries?: number },
	): Promise<{ status: number, body: unknown }> {
		try {
			const retries = options?.retries || 1;
			for (let attempt = 0; attempt < retries; attempt++) {
				const result = await this.postOnce(path, requestBody);
				if (result.status < 500) {
					return result;
				}
			}
			throw new Error("unavailable after retry attempts");
		} catch (e) {
			console.error("failed to POST", path, "because", e);
			return {
				status: 503,
				body: {},
			};
		}
	}

	async postOnce(
		path: string,
		requestBody: Serializable,
	): Promise<{ status: number, body: unknown }> {
		if (!path.startsWith("/")) {
			throw new Error("path must start with / but was (" + path + ")");
		}

		const domain = await this.chooseDomain();
		try {
			const response = await fetch(`https://${domain}${path}`, {
				method: "POST",
				body: serialize(requestBody),
				mode: "cors",
				headers: {
					"Content-Type": "application/json",
				},
				credentials: "include",
			});

			if (response.status >= 500) {
				this.markDomainHealth(domain, "unhealthy");
			}

			return {
				status: response.status,
				body: await response.json(),
			}
		} catch (e) {
			console.error(e);
			this.markDomainHealth(domain, "unhealthy");
			return {
				status: 501,
				body: {},
			};
		}
	}
}
