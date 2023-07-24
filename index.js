import * as jose from "jose";
import * as crypto from "crypto";
import ec from "elliptic";
import { ethers } from "ethers";
import { privateKeyToAccount } from "web3-eth-accounts";

async function test() {
  // Generaete Keypair
  const keypair = crypto.generateKeyPairSync("ec", {
    namedCurve: "secp256k1",
  });

  // const secondKeyPair = crypto.generateKeyPairSync("ec", {
  //   namedCurve: "secp256k1",
  // });

  // sign
  const jwt = await new jose.SignJWT({
    hello: "world!",
  })
    .setProtectedHeader({ alg: "ES256K", typ: "JWT" })
    .sign(keypair.privateKey);

  // verify
  // const x = await jose.jwtVerify(jwt, keypair.publicKey); //valid
  // const x = await jose.jwtVerify(jwt, secondKeyPair.publicKey); // Invalid
  // console.log(x); // decoded jwt

  // Verify with crypto.verify
  const jwtSplit = jwt.split(".");
  const payload = Buffer.concat([
    Buffer.from(jwtSplit[0], "utf-8"),
    Buffer.from(".", "utf-8"),
    Buffer.from(jwtSplit[1], "utf-8"),
  ]);
  const signature = Buffer.from(jwtSplit[2], "base64url");

  console.log({ payloadUint8: new Uint8Array(payload) });
  console.log({ signatureUint8: new Uint8Array(signature) });

  const verification = crypto.verify(
    "sha256",
    new Uint8Array(payload),
    { dsaEncoding: "ieee-p1363", key: keypair.publicKey },
    new Uint8Array(signature)
  );

  console.log({ verification });

  // Verify with ethers.utils.recoverAddress
  // const jwtSplit = jwt.split(".");
  // const payload = Buffer.concat([
  //   Buffer.from(jwtSplit[0], "utf-8"),
  //   Buffer.from(".", "utf-8"),
  //   Buffer.from(jwtSplit[1], "utf-8"),
  // ]);
  // const signature = Buffer.from(jwtSplit[2], "base64url");

  // console.log({ payloadUint8: new Uint8Array(payload) });
  // console.log({ signatureUint8: new Uint8Array(signature) });

  // const payloadDigest = crypto
  //   .createHash("sha256")
  //   .update(new Uint8Array(payload))
  //   .digest();
  // console.log(ethers.utils.recoverAddress(payloadDigest, signature));
  // const privateKey = Buffer.from(
  //   keypair.privateKey.export({
  //     format: "jwk",
  //   }).d,
  //   "base64url"
  // ).toString("hex");

  // console.log(privateKeyToAccount("0x" + privateKey).address);
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

async function signToJwt(payload, privateKey) {
  const { privateKeypair } = await keyPairFromPrivateKey(privateKey);

  const jwt = await new jose.SignJWT(payload)
    .setProtectedHeader({ alg: "ES256K", typ: "JWT" })
    .sign(privateKeypair);

  return jwt;
}

async function verifyJwt(jwt, address) {
  const jwtSplit = jwt.split(".");
  const payload = Buffer.concat([
    Buffer.from(jwtSplit[0], "utf-8"),
    Buffer.from(".", "utf-8"),
    Buffer.from(jwtSplit[1], "utf-8"),
  ]);
  const signature = Buffer.from(jwtSplit[2], "base64url");

  const payloadDigest = crypto.createHash("sha256").update(payload).digest();

  const recoveredAddress = ethers.utils.recoverAddress(
    payloadDigest,
    signature
  );

  console.log({
    recoveredAddress,
    address,
  });
  return recoveredAddress === address;
}

async function verifyWithCryptoVerify(jwt, publicKeypair) {
  const jwtSplit = jwt.split(".");
  const payload = Buffer.concat([
    Buffer.from(jwtSplit[0], "utf-8"),
    Buffer.from(".", "utf-8"),
    Buffer.from(jwtSplit[1], "utf-8"),
  ]);
  const signature = Buffer.from(jwtSplit[2], "base64url");

  const verification = crypto.verify(
    "sha256",
    new Uint8Array(payload),
    { dsaEncoding: "ieee-p1363", key: publicKeypair },
    new Uint8Array(signature)
  );

  return verification;
}

async function main() {
  const randomPrivateKey = crypto.randomBytes(32).toString("hex");
  const jwt = await signToJwt(
    {
      hello: "World!",
    },
    randomPrivateKey
  );

  console.log(jwt);

  // Verify with ethers
  const address = privateKeyToAccount("0x" + randomPrivateKey).address;
  console.log({ ethers: await verifyJwt(jwt, address) });

  // Verify with crypto.verify
  const { publicKeypair } = await keyPairFromPrivateKey(randomPrivateKey);
  console.log({
    cryptoverify: await verifyWithCryptoVerify(jwt, publicKeypair),
  });
}

main().catch(console.log);
