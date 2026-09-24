/**
 * Cross-platform protocol fixture, produced by the extension's own crypto.
 *
 *   node --experimental-strip-types tools/protocol-fixture.ts generate
 *     writes app/src/test/resources/protocol-fixture.json (Chrome -> Android)
 *   node --experimental-strip-types tools/protocol-fixture.ts verify <file>
 *     decrypts an envelope the Kotlin tests wrote (Android -> Chrome)
 */
import { generateKeyPairSync } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  decryptClipboardItem,
  encryptClipboardItem,
  pairingFingerprint,
  signDeviceApproval,
} from "../../extension/src/crypto/crypto-core.ts";
import {
  buildClipboardEnvelopeSignatureMessage,
  buildDeviceApprovalMessage,
  buildDeviceManagementMessage,
  buildDeviceRecoveryMessage,
  buildKeyWrapContext,
  buildPairingFingerprintContext,
  buildPayloadAad,
  buildSocketAuthMessage,
} from "../../extension/src/crypto/protocol.ts";
import { createDeviceIdentityForTesting } from "../../extension/src/crypto/key-store.ts";
import {
  CLIPBOARD_BUNDLE_V1_MIME,
  decodeClipboardBundleV1,
  encodeClipboardBundleV1,
} from "../../extension/src/clipboard/payload.ts";

const here = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(here, "../app/src/test/resources/protocol-fixture.json");
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64");
const fromUrl = (value: string) => Buffer.from(value, "base64url").toString("base64");

async function identityFrom(
  userId: string,
  deviceId: string,
  keys: { signing: { d: string; x: string }; encryption: { d: string; x: string } },
) {
  const subtle = globalThis.crypto.subtle;
  const jwk = (crv: string, k: { d: string; x: string }) => ({
    kty: "OKP", crv, d: Buffer.from(k.d, "base64").toString("base64url"),
    x: Buffer.from(k.x, "base64").toString("base64url"),
  });
  const pub = (crv: string, k: { x: string }) => ({
    kty: "OKP", crv, x: Buffer.from(k.x, "base64").toString("base64url"),
  });
  return createDeviceIdentityForTesting({
    userId,
    deviceId,
    keyVersion: 1,
    signingPrivateKey: await subtle.importKey("jwk", jwk("Ed25519", keys.signing), "Ed25519", false, ["sign"]),
    signingPublicKey: await subtle.importKey("jwk", pub("Ed25519", keys.signing), "Ed25519", true, ["verify"]),
    encryptionPrivateKey: await subtle.importKey("jwk", jwk("X25519", keys.encryption), "X25519", false, ["deriveBits"]),
    encryptionPublicKey: await subtle.importKey("jwk", pub("X25519", keys.encryption), "X25519", true, []),
  });
}

function newKeys() {
  const pair = (type: "ed25519" | "x25519") => {
    const jwk = generateKeyPairSync(type).privateKey.export({ format: "jwk" }) as { d: string; x: string };
    return { d: fromUrl(jwk.d), x: fromUrl(jwk.x) };
  };
  return { signing: pair("ed25519"), encryption: pair("x25519") };
}

async function generate() {
  const userId = "507f1f77bcf86cd799439011";
  const chromeId = "00000000-0000-4000-8000-000000000001";
  const androidId = "00000000-0000-4000-8000-000000000002";
  const chromeKeys = newKeys();
  const androidKeys = newKeys();
  const chrome = await identityFrom(userId, chromeId, chromeKeys);
  const android = await identityFrom(userId, androidId, androidKeys);
  const expiresAt = "2026-09-23T12:00:00.000Z";
  const plaintext = "héllo 👋 Copyyt\nline two";

  const envelope = await encryptClipboardItem({
    userId,
    identity: chrome,
    plaintext,
    contentType: "text/plain",
    expiresAt,
    itemId: "22222222-2222-4222-8222-222222222222",
    recipients: [{
      userId, deviceId: androidId, keyVersion: 1,
      encryptionPublicKey: androidKeys.encryption.x, trustState: "verified",
    }],
  });
  // An image bundle as the extension sends it to an image-capable device.
  const bundlePayload = {
    version: 1 as const,
    representations: [
      { mime: "text/plain" as const, encoding: "utf-8" as const, data: "caption 👋" },
      { mime: "text/html" as const, encoding: "utf-8" as const, data: "<b>caption</b> 👋" },
      { mime: "image/png" as const, encoding: "base64" as const, data: "iVBORw0KGgoBAgM=" },
    ],
  };
  const bundleEnvelope = await encryptClipboardItem({
    userId,
    identity: chrome,
    plaintext: encodeClipboardBundleV1(bundlePayload),
    contentType: CLIPBOARD_BUNDLE_V1_MIME,
    expiresAt,
    itemId: "33333333-3333-4333-8333-333333333333",
    recipients: [{
      userId, deviceId: androidId, keyVersion: 1,
      encryptionPublicKey: androidKeys.encryption.x, trustState: "verified",
    }],
  });
  const approvalSignature = await signDeviceApproval({
    userId,
    approvingIdentity: chrome,
    pendingDevice: {
      pendingDeviceId: androidId,
      pendingKeyVersion: 1,
      pendingEncryptionPublicKey: androidKeys.encryption.x,
      pendingSigningPublicKey: androidKeys.signing.x,
    },
  });
  const fingerprintInput = {
    userId,
    approvingDeviceId: chromeId, approvingKeyVersion: 1,
    approvingSigningPublicKey: chromeKeys.signing.x,
    approvingEncryptionPublicKey: chromeKeys.encryption.x,
    pendingDeviceId: androidId, pendingKeyVersion: 1,
    pendingSigningPublicKey: androidKeys.signing.x,
    pendingEncryptionPublicKey: androidKeys.encryption.x,
  };
  const managementInput = {
    action: "update" as const, userId,
    requestingDeviceId: androidId, requestingKeyVersion: 1,
    targetDeviceId: androidId, targetKeyVersion: 1,
    timestamp: 1790161602123, nonce: "5f0e2a0c-7a61-4c7e-9a38-0c1f5b1a2d44",
    name: "Android — Pixel 9 \"test\"", platform: "android",
    capabilities: ["clipboard"], appVersion: "0.1.0",
  };
  // Recovery credential exactly as the extension exports it (PKCS#8 Ed25519).
  const recoveryPair = generateKeyPairSync("ed25519");
  const recoveryPkcs8 = (recoveryPair.privateKey.export({ format: "der", type: "pkcs8" }) as Buffer).toString("base64");
  const recoveryJwk = recoveryPair.privateKey.export({ format: "jwk" }) as { d: string; x: string };
  const recoveryInput = {
    userId, rootDeviceId: chromeId, deviceId: androidId, name: "Android · Pixel 9",
    platform: "android", encryptionPublicKey: androidKeys.encryption.x,
    signingPublicKey: androidKeys.signing.x, capabilities: ["clipboard"], appVersion: "0.2.0",
    timestamp: 1790161602123, nonce: "0b8a3df6-5d4c-4c48-8c56-efb31fdb71bc",
    newRecoveryPublicKey: chromeKeys.signing.x,
  };
  const fixture = {
    userId, chromeId, androidId, chromeKeys, androidKeys, expiresAt, plaintext,
    envelope,
    bundlePayload,
    bundleEnvelope,
    approvalSignature,
    fingerprint: await pairingFingerprint(fingerprintInput),
    canonical: {
      approval: b64(buildDeviceApprovalMessage({
        userId, approvingDeviceId: chromeId, approvingKeyVersion: 1,
        pendingDeviceId: androidId, pendingKeyVersion: 1,
        pendingEncryptionPublicKey: androidKeys.encryption.x,
        pendingSigningPublicKey: androidKeys.signing.x,
      })),
      management: b64(buildDeviceManagementMessage(managementInput)),
      managementInput,
      socketAuth: b64(buildSocketAuthMessage({
        userId, deviceId: androidId, keyVersion: 1, socketId: "socket-123", challenge: "AQIDBA==",
      })),
      envelopeSignature: b64(await buildClipboardEnvelopeSignatureMessage({ userId, ...envelope })),
      keyWrap: b64(buildKeyWrapContext({
        userId, protocolVersion: 1, itemId: envelope.itemId, sourceDeviceId: chromeId,
        sourceKeyVersion: 1, recipientDeviceId: androidId, recipientKeyVersion: 1,
      })),
      payloadAad: b64(buildPayloadAad({
        userId, protocolVersion: 1, itemId: envelope.itemId, sourceDeviceId: chromeId,
        sourceKeyVersion: 1, contentType: "text/plain", expiresAt,
      })),
      fingerprintContext: b64(buildPairingFingerprintContext(fingerprintInput)),
      recovery: b64(buildDeviceRecoveryMessage(recoveryInput)),
      recoveryInput,
    },
    recoveryCredential: {
      pkcs8: recoveryPkcs8,
      seed: fromUrl(recoveryJwk.d),
      publicKey: fromUrl(recoveryJwk.x),
    },
  };
  writeFileSync(fixturePath, `${JSON.stringify(fixture, null, 2)}\n`);
  console.log(`wrote ${fixturePath}`);
}

async function verify(file: string) {
  const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
  const envelope = JSON.parse(readFileSync(file, "utf8"));
  const chrome = await identityFrom(fixture.userId, fixture.chromeId, fixture.chromeKeys);
  const { plaintext } = await decryptClipboardItem({
    userId: fixture.userId,
    identity: chrome,
    envelope,
    sourceDevice: {
      userId: fixture.userId, deviceId: fixture.androidId, keyVersion: 1,
      encryptionPublicKey: fixture.androidKeys.encryption.x,
      signingPublicKey: fixture.androidKeys.signing.x, trustState: "verified",
    },
  });
  if (envelope.contentType === CLIPBOARD_BUNDLE_V1_MIME) {
    const bytes = typeof plaintext === "string" ? new TextEncoder().encode(plaintext) : plaintext;
    const payload = decodeClipboardBundleV1(bytes);
    console.log(`extension decoded Android bundle: ${JSON.stringify(payload.representations.map((r) => r.mime))}`);
    return;
  }
  console.log(`extension decrypted Android envelope: ${JSON.stringify(plaintext)}`);
}

const [mode, file] = process.argv.slice(2);
if (mode === "generate") await generate();
else if (mode === "verify" && file) await verify(file);
else throw new Error("usage: generate | verify <envelope.json>");
