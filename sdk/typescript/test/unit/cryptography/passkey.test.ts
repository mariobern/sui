// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { beforeAll, describe, expect, it, vi } from 'vitest';
import { PasskeyKeypair } from '../../../src/keypairs/passkey';

describe('passkey signer E2E testing', () => {
	beforeAll(async () => {
		Object.defineProperty(global, 'navigator', {
			value: {
			  credentials: {
				create: vi.fn().mockResolvedValue({
				  response: {
				getPublicKey: () => new Uint8Array([48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66, 0, 4, 251, 111, 119, 15, 207, 139, 125, 206, 97, 113, 122, 153, 66, 251, 195, 128, 160, 202, 247, 143, 29, 106, 220, 187, 143, 255, 109, 5, 75, 39, 93, 172, 151, 102, 117, 50, 144, 104, 124, 243, 74, 110, 253, 245, 254, 62, 235, 108, 69, 26, 47, 65, 52, 190, 229, 83, 245, 177, 194, 19, 128, 60, 224, 50]),
					authenticatorData: new Uint8Array([1, 2, 3]),
					clientDataJSON: new TextEncoder().encode(JSON.stringify({
					  type: 'webauthn.create',
					  challenge: 'test-challenge',
					  origin: 'https://test.com'
					})),
				  }
				}),
				get: vi.fn().mockResolvedValue({
				  response: {
					authenticatorData: new Uint8Array([1, 2, 3]),
					clientDataJSON: new TextEncoder().encode(JSON.stringify({
					  type: 'webauthn.get',
					  challenge: 'test-challenge',
					  origin: 'https://test.com'
					})),
					signature: new Uint8Array([2, 206, 247, 207, 199, 93, 204, 84, 155, 28, 71, 51, 29, 130, 145, 68, 138, 241, 162, 136, 194, 246, 116, 168, 84, 165, 131, 45, 80, 37, 204, 198, 212, 113, 128, 187, 203, 75, 177, 82, 169, 30, 7, 152, 245, 159, 245, 205, 195, 145, 213, 135, 89, 183, 226, 108, 125, 68, 140, 210, 6, 228, 249, 235, 70, 2, 203, 89, 215, 175, 105, 121, 251, 98, 156, 112, 101, 56, 106, 115, 116, 252, 244, 226, 6, 151, 75, 170, 70, 112, 254, 199, 50, 135, 3, 186, 62, 166])
				  }
				})
			  }
			},
			writable: true
		  });
		});

	it('should retrieve the correct sui address', async () => {
		let signer = await PasskeyKeypair.getPasskeyInstance();
		const publicKey = signer.getPublicKey();
		expect(publicKey.toSuiAddress()).toEqual(
			'0x206100db0464975e66263d58c40959085a134eac07c686d7f1e5d0d89c1499bd',
		);
	});

	it('should sign a message and verify against pubkey', async () => {
		let signer = await PasskeyKeypair.getPasskeyInstance();
		// Define a test message
		const testMessage = 'Hello world!';
		const messageBytes = new TextEncoder().encode(testMessage);

		// Sign the test message
		const { signature } = await signer.signPersonalMessage(messageBytes);

		// verify signature against pubkey
		const publicKey = signer.getPublicKey();
		const isValid = await publicKey.verifyPersonalMessage(messageBytes, signature);
		expect(isValid).toBe(true);
	});
});
