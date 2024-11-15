// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { fromBase64 } from '@mysten/bcs';
import { secp256r1 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';

import { bytesEqual, PublicKey } from '../../cryptography/publickey.js';
import type { PublicKeyInitData } from '../../cryptography/publickey.js';
import { SIGNATURE_SCHEME_TO_FLAG } from '../../cryptography/signature-scheme.js';
import { PasskeyAuthenticator } from '../../bcs/bcs.js';

const PASSKEY_PUBLIC_KEY_SIZE = 33;

/**
 * A passkey public key
 */
export class PasskeyPublicKey extends PublicKey {
	static SIZE = PASSKEY_PUBLIC_KEY_SIZE;
	private data: Uint8Array;

	/**
	 * Create a new PasskeyPublicKey object
	 * @param value passkey public key as buffer or base-64 encoded string
	 */
	constructor(value: PublicKeyInitData) {
		super();

		if (typeof value === 'string') {
			this.data = fromBase64(value);
		} else if (value instanceof Uint8Array) {
			this.data = value;
		} else {
			this.data = Uint8Array.from(value);
		}

		if (this.data.length !== PASSKEY_PUBLIC_KEY_SIZE) {
			throw new Error(
				`Invalid public key input. Expected ${PASSKEY_PUBLIC_KEY_SIZE} bytes, got ${this.data.length}`,
			);
		}
	}

	/**
	 * Checks if two passkey public keys are equal
	 */
	override equals(publicKey: PasskeyPublicKey): boolean {
		return super.equals(publicKey);
	}

	/**
	 * Return the byte array representation of the Secp256r1 public key
	 */
	toRawBytes(): Uint8Array {
		return this.data;
	}

	/**
	 * Return the Sui address associated with this Secp256r1 public key
	 */
	flag(): number {
		return SIGNATURE_SCHEME_TO_FLAG['Passkey'];
	}

	/**
	 * Verifies that the signature is valid for for the provided message
	 */
	async verify(message: Uint8Array, signature: Uint8Array | string): Promise<boolean> {
		const parsed = parseSerializedPasskeySignature(signature);
		const clientDataJSON = JSON.parse(parsed.clientDataJson);
		const parsedChallenge = new Uint8Array(Buffer.from(clientDataJSON.challenge, 'base64url'));
		if (!bytesEqual(message, parsedChallenge)) {
		  return false
		}
		const payload = new Uint8Array([...parsed.authenticatorData, ...sha256(parsed.clientDataJson)])
		let sig = parsed.userSignature.slice(1, 64 + 1);
		let pk = parsed.userSignature.slice(1 + 64);
		if (!bytesEqual(this.toRawBytes(), pk)) {
			return false;
		}
		return secp256r1.verify(sig, sha256(payload), pk);
	}
}

export function parseSerializedPasskeySignature(signature: Uint8Array | string) {
	const bytes = typeof signature === 'string' ? fromBase64(signature) : signature;

	if (bytes[0] !== SIGNATURE_SCHEME_TO_FLAG.Passkey) {
		throw new Error('Invalid signature scheme');
	}
	const dec = PasskeyAuthenticator.parse(bytes.slice(1))
	return {
		authenticatorData: new Uint8Array(dec.authenticatorData),
		clientDataJson: dec.clientDataJson,
		userSignature: new Uint8Array(dec.userSignature),
	};
}
