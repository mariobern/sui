// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { secp256r1 } from '@noble/curves/p256';
import { randomBytes } from '@noble/hashes/utils';
import type { PublicKey } from '../../cryptography/publickey.js';
import type { SignatureScheme } from '../../cryptography/signature-scheme.js';
import { PasskeyPublicKey } from './publickey.js';
import { AuthenticationCredential, RegistrationCredential } from '@simplewebauthn/typescript-types'
import { PasskeyAuthenticator } from '../../bcs/bcs.js';
import { toHex } from '@mysten/bcs';
import { Signer } from '../../cryptography/index.js';

/**
 * Configuration options for initializing the AwsKmsSigner.
 */
export interface PasskeyKeypairData {
	/** Public key */
	publicKey: Uint8Array;
}

/**
 * An Secp256r1 Keypair used for signing transactions.
 */
export class PasskeyKeypair extends Signer {
	private keypair: PasskeyKeypairData;

	/**
	 * Get the key scheme of the keypair Secp256r1
	 */
	getKeyScheme(): SignatureScheme {
		return 'Passkey';
	}

	/**
	 * Creates an instance of AwsKmsSigner. It's expected to call the static `fromKeyId` method to create an instance.
	 * For example:
	 * ```
	 * const signer = await AwsKmsSigner.fromKeyId(keyId, options);
	 * ```
	 * @throws Will throw an error if the public key is not provided.
	 */
	constructor(keypair : PasskeyKeypairData) {
		super();
		this.keypair = keypair;
	}

	static async getPasskeyInstance(
		options?: { mock?: boolean },
	): Promise<PasskeyKeypair> {
		if (options?.mock) {
			throw new Error('Not implemented');
		} else {
			const credential = (await navigator.credentials.create({
				publicKey: {
				  // The challenge is not important here. It would normally be used to verify the attestation.
				  challenge: new TextEncoder().encode("Don't trust, verify!"),
				  rp: {
					name: 'Sui WebAuthn POC'
				  },
				  user: {
					id: randomBytes(10),
					name: 'wallet-user',
					displayName: 'Wallet User',
				  },
				  pubKeyCredParams: [{ alg: -7, type: 'public-key' }], // -7 is ES256
				  authenticatorSelection: {
					authenticatorAttachment: 'cross-platform',
					residentKey: 'required',
					requireResidentKey: true, // this may already be default
					userVerification: 'required',
				  },
				  timeout: 60000,
				  extensions: {
					largeBlob: {
					  support: 'preferred',
					},
				  } as any,
				},
			  })) as RegistrationCredential
	
			  const derSPKI = credential.response.getPublicKey()!
			  const pubkeyUncompressed = parseDerSPKI(new Uint8Array(derSPKI))
			  const pubkey = secp256r1.ProjectivePoint.fromHex(pubkeyUncompressed)
			  const pubkeyCompressed = pubkey.toRawBytes(true)
			return new PasskeyKeypair({
				publicKey: pubkeyCompressed,
			});
		}
	}

	/**
	 * The public key for this keypair
	 */
	getPublicKey(): PublicKey {
		return new PasskeyPublicKey(this.keypair.publicKey);
	}


	/**
	 * Return the signature for the provided data.
	 */
	async sign(data: Uint8Array) {
		const credential = (await navigator.credentials.get({
			publicKey: {
			  challenge: data,
			  userVerification: 'preferred',
			},
		  })) as AuthenticationCredential
		  const authenticatorData = new Uint8Array(credential.response.authenticatorData)
		  const clientDataJSON = new Uint8Array(credential.response.clientDataJSON) // response.clientDataJSON is already UTF-8 encoded JSON
		  const decoder = new TextDecoder('utf-8');
		  const clientDataJSONString: string = decoder.decode(clientDataJSON);
		  const sig = secp256r1.Signature.fromDER(
			new Uint8Array(credential.response.signature)
		  )
		  let normalized = sig.normalizeS().toCompactRawBytes()
		  const compressedPubkey = secp256r1.ProjectivePoint.fromHex(toHex(this.keypair.publicKey)).toRawBytes(true)
		  const concatenatedArray = new Uint8Array(1+normalized.length + compressedPubkey.length);
		  concatenatedArray.set([0x02]); // r1
		  concatenatedArray.set(normalized, 1);
		  concatenatedArray.set(compressedPubkey, 1+ normalized.length);
		
		  let passkeyBytes = PasskeyAuthenticator
		  .serialize({
			authenticatorData: authenticatorData,
			clientDataJson: clientDataJSONString,
			userSignature: concatenatedArray,
		  })
		  .toBytes();
		
		  const arr = new Uint8Array(1+passkeyBytes.length);
		  arr.set([0x06]);
		  arr.set(passkeyBytes, 1);
		  return arr;
		
	}
}

/**
 * Parses a DER SubjectPublicKeyInfo into an uncompressed public key. This also verifies
 * that the curve used is P-256 (secp256r1).
 *
 * @param data: DER SubjectPublicKeyInfo
 * @returns uncompressed public key (`0x04 || x || y`)
 */
export function parseDerSPKI(derBytes: Uint8Array): Uint8Array {
  console.log('derBytes', derBytes);
    // DER structure for P-256 SPKI:
  // 30 -- SEQUENCE
  //   81 -- length
  //   30 -- SEQUENCE
  //     13 -- length
  //     06 -- OBJECT IDENTIFIER
  //       07 -- length
  //       2A 86 48 CE 3D 02 01 -- id-ecPublicKey
  //     06 -- OBJECT IDENTIFIER
  //       08 -- length
  //       2A 86 48 CE 3D 03 01 07 -- secp256r1/prime256v1
  //   03 -- BIT STRING
  //     6A -- length
  //     00 -- padding
  //     04 || x || y -- uncompressed point

  // Find the start of the bit string containing the key
  const pubKeyStart = derBytes.findIndex((byte, i) => 
    byte === 0x03 && derBytes[i + 2] === 0x00 && derBytes[i + 3] === 0x04);
  
  if (pubKeyStart === -1) throw new Error('Invalid DER SPKI format');
  
  // Skip the BitString header (0x03), length byte, and padding byte (0x00)
  const rawPubKey = derBytes.slice(pubKeyStart + 3);
  return rawPubKey;
  }