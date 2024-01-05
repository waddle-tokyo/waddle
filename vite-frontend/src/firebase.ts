import * as firebaseApp from "firebase/app";
import { DiscoveryClient } from "./discovery";

const FIREBASE_JSON_PATH = "/__/firebase/init.json";

let firebaseConfig;
try {
	firebaseConfig = await (await fetch(FIREBASE_JSON_PATH)).json();
} catch (e) {
	console.error("cannot load firebase config from " + FIREBASE_JSON_PATH, e);
	throw e;
}

export const app = firebaseApp.initializeApp(firebaseConfig);

export const discovery = new DiscoveryClient("api", app);
discovery.refreshList();
