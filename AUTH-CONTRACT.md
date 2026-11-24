# Identity API v1 · shared candidate

All routes below are under /api/v1. Browser requests use same-origin JSON and the HttpOnly sc_session cookie. Session identity derives from the server. Never send an organization header to authorize a request. All roles and memberships are rechecked on the server. IDs are opaque to clients.

| Method and path | JSON body | Successful result |
|---|---|---|
| POST /auth/register | username, password, organization | 201 and signed-in session as admin of a new organization |
| POST /auth/login | username, password, optional otp | 200 and signed-in session. Valid password with missing factor returns 401 with code mfa_required |
| GET /auth/me | — | 200 authenticated session or 401 |
| POST /auth/logout | {} | 200 and expired cookie |
| POST /auth/switch | organization_id | 200 and rotated cookie for an existing membership |
| GET /members | — | Admin only, {members:[{id,username,role}]} |
| POST /members/{user_id}/role | role | Admin only, {ok:true} |
| DELETE /members/{user_id} | — | Admin only, {ok:true}; last admin protected |
| GET /invitations | — | Admin only, {invitations:[{id,username,role,expires_at,accepted_at,revoked_at}]} |
| POST /invitations | username, role | Admin only, 201, {id,token,expires_at}; hand over token privately |
| DELETE /invitations/{id} | — | Admin only, {ok:true} |
| POST /auth/accept-invitation | token, username, password, optional otp | Existing account proves credentials; new account registers. 200, signs into inviting organization |
| POST /auth/2fa/setup | password | 200 {secret,otpauth_uri}; enter in authenticator app |
| POST /auth/2fa/confirm | password, otp | 200 and rotated session, mfa_enabled true |
| POST /auth/2fa/disable | password, otp | 200 and rotated session, mfa_enabled false |
| POST /tokens | name, optional scope (ingest or read) | Admin only, 201 {id,token,scope,...}. Ingest is default. Only ingest returns install_command |
| GET /tokens, DELETE /tokens/{id} | — | Admin only, current organization |
 
Session responses for me/register/login/switch/accept/2fa confirm or disable have {authenticated:true,user:{id,username,role,mfa_enabled},organization:{id,name},memberships:[{id,name,role}],public_url}. Roles: admin, operator, viewer. All may view hosts, overview, activity, digest, work-board, events and alerts. Admin/operator may acknowledge alerts. Audit routes and membership/token management require admin; overview.audit is [] for others. Read tokens may GET monitoring routes only. Agent ingest tokens send telemetry and bind to one host. Ordinary failures use {error,message?}; 400 invalid input, 401 authentication, 403 permission, 404 resource, 409 conflict, 429 rate limit. Registration passwords 12–128 characters, usernames 3–128 letters/digits and ._@+-. Bootstrap legacy usernames still sign in. Invitations expire after 48 hours and are single-use. TOTP uses SHA1, six digits and 30-second periods, accepting a one-period clock offset. No third-party keys or email delivery required.

Storage design: identity plus legacy tenant resources in the configured SQLite database. Each additional organization has its own SQLite database under <db-path>.tenants/. Back up identity AND tenant databases together; quiesce writes for a consistent multi-file restore. Only the migrated default organization (ID 1) can opt into a legacy host view. This requires an explicit administrator setting on the server (SWARMCONTROL_ACTIVITY_ROOTS or SWARMCONTROL_ACTIVITY_ADAPTERS), and is used only until that organization receives its first remote snapshot. All other organizations always read only their registered observers’ data.

## Browser sessions and machine credentials

The organization selector accepts a positive integer or its decimal string, as emitted by a browser select. A role in the request body or an organization header cannot grant access. The bootstrap password initializes a new directory only. Legacy admin accounts retain their credentials and membership. A successful login upgrades older PBKDF2 work factors in place.

Session IDs are random, expire after 12 hours and are stored as digests. If SWARMCONTROL_SESSION_SECRET is configured, the digest is keyed and rotating that key invalidates browser sessions. Logout revokes one session. Changing the active organization rotates it. Removing a membership revokes sessions for that membership. Changes to a second factor replace all sessions for that account. Invitations bind an exact, case-sensitive username to an organization and role. A fresh invitation cancels older active invitations for the same username and organization. Return or share the invitation token once. Use a URL fragment such as `/#invite=<token>` for browser handoff so proxies do not receive the secret.

Use `SWARMCONTROL_REGISTRATION=closed` for invitation-only instances. Registration defaults to open and allows 20 attempts per client address per hour. Authentication reserves attempts before verifying credentials. The default limits are five failures per username and address and twenty per address in fifteen minutes. Configure trusted proxy addresses at the origin. Counters are process-local.

Cookie flags include HttpOnly, SameSite=Lax and Path=/. HTTPS adds Secure. Cookie-authenticated writes require a same-origin browser request. Set `SWARMCONTROL_PUBLIC_URL` to the external HTTPS origin behind a proxy. Native TLS accepts `--tls-cert CERT --tls-key KEY` or `SWARMCONTROL_TLS_CERT` and `SWARMCONTROL_TLS_KEY`. Public and protected GET routes also support HEAD. Installer scripts, detector, shipper, observer and `/agent/activity_core.py` are public downloads. Monitoring, identity and audit data require credentials.

A read token permits GET and HEAD on overview, hosts, alerts, events, digest, activity and work-board in its issuing organization. Ingest tokens may post only heartbeat, event and activity. The host binding and resource write commit together. A rejected snapshot leaves a first-use token unbound. Machine credentials remain active until revoked. Revocation invalidates both API use and the host reservation. Numeric resource IDs may repeat between organizations. Neither an ID nor a token's routing prefix authorizes access.

## Migration, audit and recovery

The resource schema is versioned in `resource_migrations`. The shared directory uses `identity_migrations`. Startup applies changes transactionally, preserves legacy tokens, host bindings, host data and audit history, and rejects unsupported newer schema versions. Legacy signed cookies require a fresh login. The existing database remains the default organization's resource database. New organizations use sibling files of the form `<configured-db>.tenants/<id>.sqlite3`.

Identity changes and resource mutations append audit records within their own transactions. The default organization continues its existing audit chain. Other organizations have two independently verifiable chains, one per store. GET /audit returns recent entries labeled with their stream. GET /audit/verify returns both stream counts and heads in `streams` as well as overall status. Hashes detect modified records or a missing intermediate record. Off-host anchoring would be needed to detect replacement of an entire database or deletion of its tail.

Back up the directory, every tenant database and the configured session key together. Use a quiesced snapshot for one point in time across files. Restoring a snapshot also restores its unexpired sessions and invitations, and any machine credentials active at the time of that snapshot. Restore to private storage and rotate credentials if recovery follows a compromise. New database files use mode 0600. TOTP seeds require protection of the database and its backups because the local verifier must read them. The current UI has no recovery codes or self-service password reset.

## Provider boundary

The local credential backend is the default. A server-side adapter can implement `CredentialProvider.authenticate` in `backend/identity_providers.py`. For WorkOS or OIDC, inject a `FederationProvider` under a server-controlled adapter name through `create_server(federation=...)`. A future trusted callback handler must validate and consume its browser authorization transaction, then call `Directory.link_federated` or `Directory.login_federated`. Linking requires the local password, an active local session and any configured second factor. Successful callbacks resolve a stored (issuer, subject) pair and reuse the same membership checks, MFA policy and revocable sessions. The current release has no external redirect route, registered application, WorkOS SDK or live Google/GitHub sign-in.

## Reproduce the identity checks

Run these commands at the root of the candidate. They use disposable databases, random local credentials and loopback HTTP or HTTPS.

```sh
python3 -m unittest discover -s tests -p test_multitenant_identity.py -v
python3 -m unittest discover -s tests -p test_identity_providers.py -v
```

The first suite registers two organizations that reuse the same host and resource IDs. It exercises isolation across monitoring and management routes, role changes, invitation replay and expiry, session revocation, MFA, legacy migration, scoped machine credentials and opt-in legacy activity. The second suite exercises the provider boundary with a simulated broker, checks a TOTP test vector and validates native HTTPS with a disposable certificate trusted only by the test client. Real third-party authentication, account recovery, cluster-wide throttling and a production load envelope remain outside these checks.
