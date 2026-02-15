# Confidential HTTP Workflow — Encoded Secrets & Encrypted Response

This workflow demonstrates:

1. **Encoded secrets** — The API key is never in config or code. It is resolved from the vault (DON secrets) via `vaultDonSecrets: [{ key: "myApiKey", owner: config.owner }]`. The header uses `{{.myApiKey}}`; the key stays encoded in the confidential request path.

2. **Response encryption** — The API response is encrypted inside the enclave before it leaves (`encryptOutput: true`). The body is AES-GCM encrypted using the vault secret `san_marino_aes_gcm_encryption_key`. The workflow outputs only the values you need to decrypt in your browser.

**Decrypt the output:** use **[CipherTools AES-GCM](https://www.ciphertools.org/tools/aes/gcm)**. The workflow prints two values to the console — copy each and paste into the tool:

| In CipherTools | What to use |
|----------------|-------------|
| **Operation** | Decrypt + verify tag |
| **Tag length** | 128 bits |
| **Key size** | 256 bit |
| **Secret key** | Your `AES_KEY_ALL` value from `.env` (64 hex characters) |
| **Nonce / IV** | The line printed as `Nonce/IV` in the console (**hex**) |
| **Ciphertext + tag input** | The line printed as `Ciphertext + tag` in the console (**hex**) |

The workflow calls [API Ninjas Jokes API](https://api.api-ninjas.com/api/jokes) with the `X-Api-Key` header (from the vault). The response is encrypted; you decrypt it locally with your key and CipherTools.

---

## 1. Environment / secrets (for simulation)

From the **project root**, use a `.env` file. The simulator maps secrets from `secrets.yaml` to env vars.

**Note:** In the workflow config (`config.staging.json` / `config.production.json`) you may see `"owner": ""`. This is intentional for local simulation: there is no real interaction with the Vault DON here, so `owner` is not required. In production, you would set the owner for vault secret access.

- **API Ninjas key** (DON secret `myApiKey`):
  ```
  MY_API_KEY_ALL=<your-api-ninjas-key>
  ```
  Get a free key at [api.ninjas.com](https://api.ninjas.com/register).

- **AES-256 key** (DON secret `san_marino_aes_gcm_encryption_key`). Same value is used as **Secret key** in CipherTools when decrypting:
  ```
  AES_KEY_ALL=<64-char-hex-string>
  ```
  Must be 256-bit (32 bytes) hex-encoded. Generate one: `openssl rand -hex 32`. Do **not** commit the real key.

Optional (for chain writes): `CRE_ETH_PRIVATE_KEY=...`

Copy from example:
```bash
cp .env.example .env
# Edit .env: set MY_API_KEY_ALL and AES_KEY_ALL.
```

---

## 2. Install dependencies

If `bun` is not installed, see https://bun.com/docs/installation.

```bash
cd my-workflow && bun install
```

---

## 3. Simulate the workflow

From the **project root**:

```bash
cre workflow simulate ./my-workflow --target=staging-settings
```

The console will print, under clear labels:

- **Nonce/IV** — one line of **hex**; paste into the “Nonce / IV” field on [CipherTools AES-GCM](https://www.ciphertools.org/tools/aes/gcm).
- **Ciphertext + tag** — one line of **hex**; paste into the “Ciphertext + tag input” field.

On CipherTools set: **Operation** = Decrypt + verify tag, **Tag length** = 128 bits, **Key size** = 256 bit, **Secret key** = your `AES_KEY_ALL` value from `.env`. Then paste the two values above; the decrypted plaintext is the API response (e.g. JSON with a joke).
