```sh
# Run this to find the CONTAINER_ID_PREFIX
docker ps

# Run this to enter the container
docker exec -it CONTAINER_ID_PREFIX /bin/sh
```

```sh
# The default working directory is the directory of the app,
# which has the appropriate `node_modules`.
node
```

```js
const firebase = await import("firebase-admin/app");
const firestore = await import("firebase-admin/firestore");

firebase.initializeApp({
	credential: firebase.applicationDefault(),
});

const db = firestore.getFirestore();

const path = db.doc(`anon-discovery/h035212144024`);
const doc = await path.get();
doc.data();
```
