import { describe, expect, it } from 'vitest';
import PACKET from 'Network/PacketStructure.js';
import TextEncoding from 'Utils/CodepageManager.js';
import { LOGIN_PASSWORD_FIELD_BYTES } from 'Utils/PasswordPolicy.js';

describe('Standard login packet 0x64', () => {
	function buildLoginPacket(password) {
		const packet = new PACKET.CA.LOGIN();

		packet.Version = 20250716;
		packet.ID = 'TestPlayer';
		packet.Passwd = password;
		packet.clienttype = 12;

		return new Uint8Array(packet.build().buffer);
	}

	it('preserves the 55-byte packet layout', () => {
		const bytes = buildLoginPacket('test123');
		const view = new DataView(bytes.buffer);

		expect(bytes.length).toBe(55);
		expect(view.getUint16(0, true)).toBe(0x64);
		expect(view.getUint32(2, true)).toBe(20250716);
		expect(bytes[54]).toBe(12);
	});

	it('preserves the null terminator for a 23-byte password', () => {
		const password = 'a'.repeat(23);
		const bytes = buildLoginPacket(password);

		expect(LOGIN_PASSWORD_FIELD_BYTES).toBe(24);
		expect(Array.from(bytes.slice(30, 53))).toEqual(
			Array.from(TextEncoding.encode(password, 'utf-8'))
		);
		expect(bytes[53]).toBe(0);
		expect(bytes[54]).toBe(12);
	});

	it('serializes multibyte UTF-8 passwords correctly', () => {
		const password = 'é'.repeat(10) + 'abc';
		const bytes = buildLoginPacket(password);

		expect(Array.from(bytes.slice(30, 53))).toEqual(
			Array.from(TextEncoding.encode(password, 'utf-8'))
		);
		expect(bytes[53]).toBe(0);
		expect(bytes.length).toBe(55);
	});
});
