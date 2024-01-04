## GitHub Actions

* **`FRONTEND_ENV_PRODUCTION` secret**: Becomes `.env.production`.
    * See [/vite-frontend/src/.env](/vite-frontend/src/.env) for required fields
      and format.
* **`GITHUB_TOKEN` secret**
* **`FIREBASE_SERVICE_ACCOUNT`, `FIREBASE_PROJECT_ID` secrets**
    * These can be created using `firebase init hosting:github`.
    * You can manually create a new key from the Google Cloud IAM page:
        * Choose the service account. It should have `Firebase Authentication Admin`, `Firebase Hosting Admin`, `Cloud Run Viewer`, `API Keys Viewer`, `Cloud Functoins Developer` roles.
        * Navigate to Keys > Add Key > Create new key.
        * Choose JSON

## Google Cloud Build

* **`PROJECT_ID`**, **`COMMIT_SHA`**
* **`_BACKEND_CONFIG_JSONC`**: Becomes `backend/conf.jsonc`
    * See [/backend/config.ts](/backend/config.ts) for required fields and format.
* **`_DOCKER_REGION`**: For example, `us-east1`.
* **`_DOCKER_CONTAINER`**: For example, `my-docker-container-name`.
* **`_TEMPLATE_SERVICE_ACOUNT`**: The `--service-account` parameter to use when
  creating an instance template.
* **`_INSTANCE_GROUP`**: The instance group name to deploy to.
* **`_INSTANCE_ZONE`** The `--zone` parameter to use for
  `gcloud instance-groups managed rolling-action start-update`.
  For example, `us-west1b`.
* **`_LOGS_BUCKET`**

### How to set up Cloud Build

* Navigate to Cloud Build > 1st Gen
* Connect Repository
* GitHub (Cloud Build GitHub App)

Create a trigger. Se the Source to the repository that was initialized above.

Define the Substitution variables above.
