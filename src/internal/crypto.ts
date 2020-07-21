import * as Internal from '.'
import * as util from '../helpers'
import { KeyPairType } from '../types'
import msrcrypto from 'msrcrypto'
import { AsyncCurve as AsyncCurveType } from '@privacyresearch/curve25519-typescript'

const webcrypto = window?.crypto || msrcrypto

export class Crypto {
    private _curve: Internal.AsyncCurve
    private _webcrypto: globalThis.Crypto

    constructor(crypto?: globalThis.Crypto) {
        this._curve = new Internal.AsyncCurve()
        this._webcrypto = crypto || webcrypto
    }

    set webcrypto(wc: globalThis.Crypto) {
        this._webcrypto = wc
    }
    set curve(c: AsyncCurveType) {
        this._curve.curve = c
    }

    getRandomBytes(n: number): ArrayBuffer {
        const array = new Uint8Array(n)
        this._webcrypto.getRandomValues(array)
        return util.uint8ArrayToArrayBuffer(array)
    }

    async encrypt(key: ArrayBuffer, data: ArrayBuffer, iv: ArrayBuffer): Promise<ArrayBuffer> {
        const impkey = await this._webcrypto.subtle.importKey('raw', key, { name: 'AES-CBC' }, false, ['encrypt'])

        return this._webcrypto.subtle.encrypt({ name: 'AES-CBC', iv: new Uint8Array(iv) }, impkey, data)
    }

    async decrypt(key: ArrayBuffer, data: ArrayBuffer, iv: ArrayBuffer): Promise<ArrayBuffer> {
        const impkey = await this._webcrypto.subtle.importKey('raw', key, { name: 'AES-CBC' }, false, ['decrypt'])

        return this._webcrypto.subtle.decrypt({ name: 'AES-CBC', iv: new Uint8Array(iv) }, impkey, data)
    }
    async sign(key: ArrayBuffer, data: ArrayBuffer): Promise<ArrayBuffer> {
        const impkey = await this._webcrypto.subtle.importKey(
            'raw',
            key,
            { name: 'HMAC', hash: { name: 'SHA-256' } },
            false,
            ['sign']
        )

        try {
            return this._webcrypto.subtle.sign({ name: 'HMAC', hash: 'SHA-256' }, impkey, data)
        } catch (e) {
            // console.log({ e, data, impkey })
            throw e
        }
    }
    async hash(data: ArrayBuffer): Promise<ArrayBuffer> {
        return this._webcrypto.subtle.digest({ name: 'SHA-512' }, data)
    }

    async HKDF(input: ArrayBuffer, salt: ArrayBuffer, info: ArrayBuffer): Promise<ArrayBuffer[]> {
        // Specific implementation of RFC 5869 that only returns the first 3 32-byte chunks
        if (typeof info === 'string') {
            throw new Error(`HKDF info was a string`)
        }
        const PRK = await Internal.crypto.sign(salt, input)
        const infoBuffer = new ArrayBuffer(info.byteLength + 1 + 32)
        const infoArray = new Uint8Array(infoBuffer)
        infoArray.set(new Uint8Array(info), 32)
        infoArray[infoArray.length - 1] = 1
        const T1 = await Internal.crypto.sign(PRK, infoBuffer.slice(32))
        infoArray.set(new Uint8Array(T1))
        infoArray[infoArray.length - 1] = 2
        const T2 = await Internal.crypto.sign(PRK, infoBuffer)
        infoArray.set(new Uint8Array(T2))
        infoArray[infoArray.length - 1] = 3
        const T3 = await Internal.crypto.sign(PRK, infoBuffer)
        return [T1, T2, T3]
    }

    // Curve25519 crypto

    createKeyPair(privKey?: ArrayBuffer): Promise<KeyPairType> {
        if (!privKey) {
            privKey = this.getRandomBytes(32)
        }
        return this._curve.createKeyPair(privKey)
    }

    ECDHE(pubKey: ArrayBuffer, privKey: ArrayBuffer): Promise<ArrayBuffer> {
        return this._curve.ECDHE(pubKey, privKey)
    }

    Ed25519Sign(privKey: ArrayBuffer, message: ArrayBuffer): Promise<ArrayBuffer> {
        return this._curve.Ed25519Sign(privKey, message)
    }

    Ed25519Verify(pubKey: ArrayBuffer, msg: ArrayBuffer, sig: ArrayBuffer): Promise<boolean> {
        return this._curve.Ed25519Verify(pubKey, msg, sig)
    }
}

export const crypto = new Crypto()

export function setWebCrypto(webcrypto: globalThis.Crypto): void {
    crypto.webcrypto = webcrypto
}

export function setCurve(curve: AsyncCurveType): void {
    crypto.curve = curve
}

// HKDF for TextSecure has a bit of additional handling - salts always end up being 32 bytes
export function HKDF(input: ArrayBuffer, salt: ArrayBuffer, info: string): Promise<ArrayBuffer[]> {
    if (salt.byteLength != 32) {
        throw new Error('Got salt of incorrect length')
    }

    const abInfo = util.binaryStringToArrayBuffer(info)
    if (!abInfo) {
        throw new Error(`Invalid HKDF info`)
    }

    return crypto.HKDF(input, salt, abInfo)
}

export async function verifyMAC(data: ArrayBuffer, key: ArrayBuffer, mac: ArrayBuffer, length: number): Promise<void> {
    const calculated_mac = await crypto.sign(key, data)
    if (mac.byteLength != length || calculated_mac.byteLength < length) {
        throw new Error('Bad MAC length')
    }
    const a = new Uint8Array(calculated_mac)
    const b = new Uint8Array(mac)
    let result = 0
    for (let i = 0; i < mac.byteLength; ++i) {
        result = result | (a[i] ^ b[i])
    }
    if (result !== 0) {
        throw new Error('Bad MAC')
    }
}

export function calculateMAC(key: ArrayBuffer, data: ArrayBuffer): Promise<ArrayBuffer> {
    return crypto.sign(key, data)
}
