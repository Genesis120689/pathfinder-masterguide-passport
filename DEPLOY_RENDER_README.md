# Pathfinder & Master Guide Digital Passport — Cloud staging package

This package is prepared for **Render paid Python web service + persistent disk**. It is **not yet approved for public member data**. The official requirements are still condensed, and the app still needs a security review, per-division isolation, account reset, backup automation and operational tests. Certification remains disabled.

## Starting clean on Render (staging only)
1. Create a **private** GitHub repository. Upload the contents of this ZIP **keeping `render.yaml` at the root and `pathfinder_passport/` as a folder**. DO NOT include your local `passport.db`, `.instance_secret`, `.setup_token`, member uploads, passwords, screenshots containing passwords or exported member lists.
2. Sign up to [Render](https://dashboard.render.com/). From **New → Blueprint**, connect the private GitHub repository and apply `render.yaml`. A **paid service and disk** may incur charges. Confirm the actual charges in Render before approving.
3. When Render requests `PASSPORT_SETUP_TOKEN`, provide a privately generated **long random value (at least 32 characters)**. Generate with Python: `python -c "import secrets; print(secrets.token_urlsafe(36))"`. Never share the token through screenshots/chat or commit it to GitHub.
4. Wait for the deployment's `/healthz` endpoint to show `{"ok":true}`. Open the Render URL. The first-admin setup screen should load on a **new, empty** cloud database. Enter your selected admin name and password and the private setup token.
5. Immediately remove `PASSPORT_SETUP_TOKEN` from the environment after successfully creating the first administrator and redeploy. Keep `PASSPORT_SECRET` stable; changing it invalidates login sessions and QR signatures.
6. Test with synthetic test members only, in at least two distinct clubs, including unauthorized access attempts. Do not collect minors' real information until the production readiness items below are complete.
7. Later add a custom domain in Render's settings and share its HTTPS URL with members only after security/authorization sign-off.

### Existing Windows records
**This starter does not automatically migrate your existing PC database to the cloud.** Your local `passport.db` and member uploads remain on your computer. Migrating them requires a controlled encrypted transfer onto the paid persistent disk, validation of the database, photos and logins, and a tested rollback procedure. Do not put the database in GitHub, email, public upload links, or an app asset folder. Preserve the original `.instance_secret` or configure an identical secret during a migration if old QR verification must remain valid.

### Technical changes relative to V1.1
- Database, runtime secret, first-admin token, announcement photos, and uploaded MG logo now use `PASSPORT_DATA_DIR`, which is mounted on Render's persistent disk.
- Browser sessions use secure cookies with `HTTPS_ONLY=1` on Render.
- `PASSPORT_SETUP_TOKEN` allows one-time remote first-admin creation; setup is disabled automatically once the first admin exists.
- `CERTIFICATION_ENABLED=0`; the existing approval gate remains closed for official certification.
- A `/healthz` endpoint has been added. The server starts with one Uvicorn worker because SQLite access is not designed for multiple shared instances.

### Must finish before members use it
- Security review: CSRF protection, login rate limiting, account recovery, audit/event monitoring, secure uploads, session invalidation, and permission tests across multiple clubs/divisions
- Actual per-division/mission access rules; current 'SSD' role codes are legacy and **not full multi-division isolation**
- Complete verified GC requirements and approved certification governance
- Automatic, encrypted off-site backups with restoration drills, and legal/privacy arrangements for children/guardian consent
- Load/concurrency tests and plan for PostgreSQL before large-scale rollout

### Expected result
You receive a cloud HTTPS address hosted by Render. It is independent from your PC, but this package alone **does not create a hosted website**, purchase hosting, or guarantee production readiness.
