# Docker Hub Publishing

The backend Docker image workflow publishes to Docker Hub only when Docker Hub
credentials are configured as GitHub repository secrets.

## Required GitHub Secrets

- `DOCKERHUB_USERNAME`: Docker Hub username or organization namespace.
- `DOCKERHUB_TOKEN`: Docker Hub personal access token.

## Optional GitHub Variable

- `DOCKERHUB_IMAGE_NAME`: Full Docker Hub image path, for example
  `your-dockerhub-username/cli-proxy-api-plus`. If omitted, the workflow uses
  `${DOCKERHUB_USERNAME}/cli-proxy-api-plus`.

## Deployment

To run the Docker Hub image with Compose, copy `.env.example` to `.env` and set:

```env
CLI_PROXY_IMAGE=your-dockerhub-username/cli-proxy-api-plus:latest
```

Then run:

```sh
docker compose up -d --remove-orphans --no-build
```
