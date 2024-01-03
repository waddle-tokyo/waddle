## GitHub Actions

* **`FRONTEND_ENV_PRODUCTION` secret**: Becomes `.env.production`.
    * See [vite-frontend/src/.env](vite-frontend/src/.env) for required fields
      and format.
* **`GITHUB_TOKEN` secret**
* **`FIREBASE_SERVICE_ACCOUNT`, `FIREBASE_PROJECT_ID` secrets**: Created by Firebase

## Google Cloud Build

* **`PROJECT_ID`**, **`COMMIT_SHA`**
* **`BACKEND_CONFIG_JSONC`**: Becomes `backend/conf.jsonc`
    * See [backend/config.ts](backend/config.ts) for required fields and format.
* **`DOCKER_REGION`**: For example, `us-east1`.
* **`DOCKER_CONTAINER`**: For example, `my-docker-container-name`.
* **`TEMPLATE_SERVICE_ACOUNT`**: The `--service-account` parameter to use when
  creating an instance template.
* **`INSTANCE_GROUP`**: The instance group name to deploy to.
* **`INSTANCE_ZONE`** The `--zone` parameter to use for
  `gcloud instance-groups managed rolling-action start-update`.
  For example, `us-west1b`.
* **`LOGS_BUCKET`**
