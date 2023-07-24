import * as jose from "jose";
import * as crypto from "crypto";
import ec from "elliptic";
import { ethers } from "ethers";

main().catch(console.log);

async function main() {
  const randomPrivateKey = crypto.randomBytes(32).toString("hex");

  // Signing
  const jwt = await signToJwt(
    {
      hello: "World!",
    },
    randomPrivateKey
  );
  console.log({ jwt });
  
  // Verifying
  const address = ethers.utils.computeAddress("0x" + randomPrivateKey)
  console.log({ verify: await verifyJwt(jwt, address) });
}

export async function signToJwt(payload, privateKey) {
  const { privateKeypair } = await keyPairFromPrivateKey(privateKey);

  const jwt = await new jose.SignJWT(payload)
    .setProtectedHeader({ alg: "ES256K", typ: "JWT" })
    .sign(privateKeypair);

  return jwt;
}

export function verifyJwt(jwt, address) {
  const { payloadDigest, signature } = getPayloadDigest(jwt);

  const recoveredAddresses = recoverAddressWithoutRecId(
    payloadDigest,
    signature
  );

  return recoveredAddresses.some(
    (recoveredAddress) => recoveredAddress === address
  );
}

async function keyPairFromPrivateKey(privateKey) {
  const c = new ec.ec("secp256k1");
  const publicKey = c.keyFromPrivate(privateKey).getPublic("hex");
  const publicX = publicKey.substring(2, 2 + 64);
  const publicY = publicKey.split(publicX)[1];

  const publicJwk = {
    kty: "EC",
    crv: "secp256k1",
    x: Buffer.from(publicX, "hex").toString("base64url"),
    y: Buffer.from(publicY, "hex").toString("base64url"),
  };

  const publicKeypair = await jose.importJWK(publicJwk);

  const privateKeypair = await jose.importJWK({
    ...publicJwk,
    d: Buffer.from(privateKey, "hex").toString("base64url"),
  });

  return { privateKeypair, publicKeypair };
}

function getPayloadDigest(jwt) {
  const jwtSplit = jwt.split(".");
  const payload = Buffer.concat([
    Buffer.from(jwtSplit[0], "utf-8"),
    Buffer.from(".", "utf-8"),
    Buffer.from(jwtSplit[1], "utf-8"),
  ]);
  const payloadDigest = crypto.createHash("sha256").update(payload).digest();

  const signature = Buffer.from(jwtSplit[2], "base64url");

  return {
    payloadDigest,
    signature,
  };
}

function recoverAddressWithoutRecId(digest, signature) {
  const recIds = [27, 28];

  return recIds.map((recId) =>
    ethers.utils.recoverAddress(
      digest,
      Buffer.concat([signature, new Uint8Array([recId])])
    )
  );
}
