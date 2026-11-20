# Deploy AegisTrace to Google Cloud Run

This repository includes a Dockerfile that listens on the `PORT` environment variable supplied by Cloud Run. The app does not require a Gemini API key; the optional AI narrative stays disabled unless a key is configured.

## Before you begin

1. Have a Google Cloud project with billing enabled.
2. Install the Google Cloud CLI and authenticate:

   ```bash
   gcloud auth login
   gcloud config set project YOUR_PROJECT_ID
   ```

3. Enable the services used for Cloud Run source deployment:

   ```bash
   gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com
   ```

## Deploy from the repository folder

Run this from the root folder containing `Dockerfile`:

```bash
gcloud run deploy aegistrace \
  --source . \
  --region asia-south1 \
  --allow-unauthenticated \
  --port 8080 \
  --cpu 1 \
  --memory 1Gi \
  --min 0 \
  --max 2
```

The `--allow-unauthenticated` option makes the app reachable by judges without requiring them to sign in. Use only synthetic/demo security logs in this public deployment. Do not use the public demo to process real organisational or personal security logs.

At the end of a successful deployment, the CLI prints a **Service URL**. Copy that exact URL from the command output or the Cloud Run service details page. Do not construct or guess the URL.

## Verify the service

1. Open the Service URL in a private/incognito browser window.
2. Confirm the AegisTrace dashboard loads without Google sign-in.
3. Run the built-in full multi-signal scenario.
4. Confirm it produces findings/incidents and that evidence and recommendations expand.
5. Test the normal baseline and confirm no incident is raised.
6. Do not upload real logs. The deployed app is for synthetic competition demonstration only.

If deployment fails, inspect the service logs:

```bash
gcloud run services logs read aegistrace --region asia-south1 --limit 100
```

## Cost and security notes

- The service is configured to scale from zero with a maximum of two instances. Cloud Run pricing depends on region, usage and billing configuration; check the current Google Cloud pricing page before deploying.
- A billing-enabled Google Cloud project is required. A free tier may apply, but do not assume the deployment is guaranteed to cost zero.
- No Gemini key is needed for the main demo. Do not place API keys in source control or in a public repository.
- A public Cloud Run URL means anyone with the URL can access the demo. The app is not an authenticated production SIEM.

Official references:
- https://docs.cloud.google.com/run/docs/deploying-source-code
- https://docs.cloud.google.com/sdk/gcloud/reference/run/deploy
- https://cloud.google.com/run/pricing
