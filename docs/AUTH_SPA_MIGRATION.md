# Auth SPA Migration

Blogsphere is introducing a dedicated Angular Auth SPA (`Blogsphere.Auth.Webapp`) to replace Identity Server Razor account pages over time. Until the feature flag is enabled, **Razor pages remain the production path** and must not be removed.

## Feature flag

Identity Server reads `AuthSpa:Enabled` from configuration (`AuthSpaOptions` in `HostingExtensions.cs`):

```json
"AuthSpa": {
  "Enabled": false,
  "BaseUrl": "http://localhost:4201"
}
```

| Setting | Default | Purpose |
|---------|---------|---------|
| `Enabled` | `false` | When `false`, OIDC/login redirects continue to Razor `/Account/*` pages. When `true`, redirects target the Auth SPA routes. |
| `BaseUrl` | `http://localhost:4201` | Root URL of the Auth SPA (dev: `ng serve --port 4201`). |

## Current state

- **Razor pages**: Still served under `/Account/*` (login, logout, consent, device flow, grants, password flows, etc.).
- **Auth SPA**: Parallel implementation at `Blogsphere.Auth.Webapp` calling `/api/account/*` JSON endpoints on Identity Server.
- **Management Webapp**: `useAuthSpa: false` by default in `environment.ts`. When set to `true`, password reset and account manage links use `authSpaBaseUrl` instead of Razor URLs.

## Enabling the Auth SPA (future)

1. Deploy `Blogsphere.Auth.Webapp` and set `AuthSpa:BaseUrl` to its public URL.
2. Set `AuthSpa:Enabled` to `true` in Identity Server configuration.
3. Set `useAuthSpa: true` in the Management Webapp environment for the target deployment.
4. Verify OIDC authorize/login, logout, consent, and password flows end-to-end.

## Do not remove Razor yet

Razor account UI is required for rollback and for environments where `AuthSpa:Enabled` is `false`. Remove Razor pages only after the Auth SPA is validated in all environments and the flag defaults to enabled.

## Local development

```bash
# Identity Server (port 5000)
# Auth SPA
cd Blogsphere.Auth.Webapp
npm start   # http://localhost:4201
```

The Auth SPA expects `environment.authority` to point at Identity Server and uses cookie + XSRF for `/api/account` calls.
