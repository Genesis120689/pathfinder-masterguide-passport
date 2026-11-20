# Pathfinder & Master Guide Digital Passport V1.0 — Approved Login Fixed

This build corrects the **actual cause** of the missing approved login artwork: V0.9 included the files but the server's allowlist returned **404 Not Found** for those assets. V1.0 explicitly serves `/assets/approved_login_artwork.webp` and `/assets/approved_main_logo.webp` and renders the artwork as a real `<img>` backdrop. The right-side login/admin-setup controls are functional HTML forms.

## Windows run

1. Extract ZIP. Double-click `START_WINDOWS.bat`.
2. Open http://127.0.0.1:8765 (Ctrl+F5 once after updating).
3. First installation: use Create First Administrator with token shown in command window. Later: sign in with existing credentials.

## Update an existing installation safely

Shut down the program; **back up** `passport.db`, `.instance_secret`, `.setup_token` (if present), and any user-uploaded images. Replace the program source/assets with these extracted files **without overwriting your old `passport.db` or `.instance_secret`**. The archive intentionally contains none of these private instance files. Restart the app. Do not overwrite files under `assets/announcements/` with an empty folder.

## Image URLs to test if artwork is blank

Visit `http://127.0.0.1:8765/assets/approved_login_artwork.webp` and `http://127.0.0.1:8765/assets/approved_main_logo.webp` directly. Both should display the respective art, not a 404.

This is a local application and not a production security audit or division-wide certification release. The requirements catalog requires verification with official curricular sources before issuing official certifications.


## V1.1 Professional Dashboard (November 2026)
- Redesigned administrator hero using the approved outdoor portrait and exact approved brand banner.
- Live six-card metrics, gold-accented announcements, improved desktop/mobile responsiveness.
- Kept server routes, account roles, checklists, and API behavior unchanged.
- **No database or secret included.** Keep existing `passport.db`, `.instance_secret`, and uploads in place when upgrading.
- Branding is division-neutral; no pilot branding.
- This is a UI upgrade, not a certification/hosting security approval.
