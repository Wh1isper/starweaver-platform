# Operations

The first operational layer is repository infrastructure: CI, pre-commit,
mdBook docs, and Cloudflare Pages deployment.

## Docs Deployment

The docs workflow builds `book/` and deploys it to Cloudflare Pages:

```text
project: starweaver-platform-docs
branch: main
output: book
```

Required GitHub secrets:

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`

Required GitHub environment:

- `docs`

## Future Release Gates

Add these gates when their artifacts exist:

- migration check
- OpenAPI schema check
- Docker build smoke
- local compose smoke
- image SBOM generation
- release artifact checksum generation
