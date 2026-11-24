# Check which version of NeuroSwarm is running

To check a deployment, compare what a browser downloads from the site with the release files you intended to deploy. Run this command from the extracted release directory. Replace the example origin with the address of your console.

```sh
python3 deploy/check_release.py https://console.example.org --candidate .
```

Exit code `0` means that the public manifest, both HTML pages and all six JavaScript and CSS files match, and the seven service checks passed. A difference, a missing file, or a network or certificate error returns a nonzero exit code. The checker fetches the same versioned URLs the browser uses and checks their decoded bytes and lengths. It fetches only from the supplied origin, using paths from the local release.

`--candidate` can point to another extracted release. By default the checker uses the checkout containing the script. For local development you may use an HTTP loopback address such as `http://127.0.0.1:8790`. Remote checks require HTTPS and a trusted certificate. Set `SSL_CERT_FILE` to use a private certificate authority.

## What the public endpoint reports

`GET /api/v1/version` returns public release metadata as JSON with `Cache-Control: no-store`. `HEAD` returns the same headers. `GET /health` includes `version_url` so clients can find the manifest.

| Field | Meaning |
| --- | --- |
| `schema_version` | The manifest format. Its current value is the integer `1`. |
| `version` | The release identifier. It starts with `sha256:` followed by 64 hexadecimal digits. |
| `runtime_sha256` | One checksum for the Python files in `backend/*.py`, `backend/adapters/*.py` and `agent/*.py`, captured when the server starts. |
| `assets` | The six public JavaScript and CSS paths. Each entry gives the SHA-256 checksum and size in bytes. The browser URL appends `?v=` and the first 12 checksum digits. |
| `pages` | Checksums and sizes for the rendered HTML at `/` and `/live`, including the versioned asset URLs. `/index.html` is an alias for `/`. |

To reproduce the runtime checksum, map each relative Python path to the SHA-256 of its file bytes, serialize the map as compact JSON with sorted keys and ASCII escaping, and hash that JSON with SHA-256. The release identifier uses the same procedure on the four other manifest fields. Git history, installation paths and file timestamps do not affect the result.

## Use the result

The runtime checksum describes the package at process startup. The server reads its static files when serving the interface, so a deployment in progress can briefly serve different versions across requests. Installed observers report their own versions.

The checker verifies the public interface bytes, the runtime identity the server reports, access controls and installer availability. To check operator access as well, sign in and follow a known event to its session. Record the date, verified release ID and sign-in result in your release log. After rolling back, rerun the same command against the files from the restored release.
