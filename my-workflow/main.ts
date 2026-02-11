import {
  CronCapability,
  ConfidentialHTTPClient,
  handler,
  consensusIdenticalAggregation,
  ok,
  type ConfidentialHTTPSendRequester,
  type Runtime,
  Runner,
} from "@chainlink/cre-sdk"
import { z } from "zod"

// Config schema
const configSchema = z.object({
  schedule: z.string(),
  url: z.string(),
  owner: z.string(),
})

type Config = z.infer<typeof configSchema>

// When encryptOutput is true, response body is encrypted: nonce (12) || ciphertext || tag (16).
type EncryptedBodyResult = { bodyBase64: string }

const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

function bytesToBase64(bytes: Uint8Array): string {
  let out = ""
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i] ?? 0
    const b = bytes[i + 1]
    const c = bytes[i + 2]
    out += BASE64_ALPHABET[a >> 2]
    out += BASE64_ALPHABET[((a & 3) << 4) | (b ?? 0) >> 4]
    out += b === undefined ? "=" : BASE64_ALPHABET[((b & 15) << 2) | (c ?? 0) >> 6]
    out += c === undefined ? "=" : BASE64_ALPHABET[c & 63]
  }
  return out
}

function base64ToBytes(base64: string): Uint8Array {
  const len = base64.replace(/=+$/, "").length
  const n = Math.floor((len * 3) / 4)
  const out = new Uint8Array(n)
  let i = 0
  let j = 0
  while (i < base64.length) {
    const a = BASE64_ALPHABET.indexOf(base64[i++] ?? "")
    const b = BASE64_ALPHABET.indexOf(base64[i++] ?? "")
    const c = BASE64_ALPHABET.indexOf(base64[i++] ?? "")
    const d = BASE64_ALPHABET.indexOf(base64[i++] ?? "")
    if (a < 0 || b < 0) break
    out[j++] = (a << 2) | (b >> 4)
    if (c >= 0 && j < n) out[j++] = ((b & 15) << 4) | (c >> 2)
    if (d >= 0 && j < n) out[j++] = ((c & 3) << 6) | d
  }
  return out
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
}

// Fetch with response encryption: enclave encrypts body before it leaves; we get encrypted bytes.
const fetchWithEncryptedResponse = (
  sendRequester: ConfidentialHTTPSendRequester,
  config: Config
): EncryptedBodyResult => {
  const response = sendRequester
    .sendRequest({
      request: {
        url: config.url,
        method: "GET",
        multiHeaders: {
          "X-Api-Key": { values: ["{{.myApiKey}}"] },
        },
      },
      vaultDonSecrets: [
        { key: "myApiKey", owner: config.owner },
        { key: "san_marino_aes_gcm_encryption_key", owner: config.owner },
      ],
      encryptOutput: true,
    })
    .result()

  if (!ok(response)) {
    throw new Error(`HTTP request failed with status: ${response.statusCode}`)
  }

  const body = response.body ?? new Uint8Array(0)
  const bodyBase64 = bytesToBase64(body)
  return { bodyBase64 }
}

const DECRYPT_URL = "https://www.ciphertools.org/tools/aes/gcm"
const DECRYPT_STEPS = [
  `Decrypt at ${DECRYPT_URL}`,
  "Operation: Decrypt + verify tag | Tag length: 128 bits | Key size: 256 bit",
  "Secret key: use your AES_KEY_ALL value from .env (64 hex chars)",
].join(" — ")

// Main workflow handler: output only values needed for CipherTools AES-GCM decrypt.
const onCronTrigger = (runtime: Runtime<Config>): string => {
  const confHTTPClient = new ConfidentialHTTPClient()

  const result = confHTTPClient
    .sendRequest(
      runtime,
      fetchWithEncryptedResponse,
      consensusIdenticalAggregation<EncryptedBodyResult>()
    )(runtime.config)
    .result()

  const bodyBytes = base64ToBytes(result.bodyBase64)
  const nonceBytes = bodyBytes.slice(0, 12)
  const ciphertextAndTagBytes = bodyBytes.slice(12)

  const nonceHex = bytesToHex(nonceBytes)
  const ciphertextAndTagHex = bytesToHex(ciphertextAndTagBytes)

  runtime.log("--- Copy-paste for CipherTools (https://www.ciphertools.org/tools/aes/gcm) ---")
  runtime.log("Ciphertext + tag (paste into Ciphertext + tag input, hex):")
  runtime.log(ciphertextAndTagHex)
  runtime.log("Nonce/IV (paste into Nonce / IV field, hex):")
  runtime.log(nonceHex)
  runtime.log("---")
  runtime.log(DECRYPT_STEPS)
  return result.bodyBase64
}

// Initialize workflow
const initWorkflow = (config: Config) => {
  return [
    handler(
      new CronCapability().trigger({
        schedule: config.schedule,
      }),
      onCronTrigger
    ),
  ]
}

export async function main() {
  const runner = await Runner.newRunner<Config>({ configSchema })
  await runner.run(initWorkflow)
}
