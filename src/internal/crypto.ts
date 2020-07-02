import * as Internal from '.'
import { KeyPairType } from '../types'

export class Crypto {
    private _curve: Internal.AsyncCurve

    constructor() {
        this._curve = new Internal.AsyncCurve()
    }

    static getRandomBytes(n: number): ArrayBuffer {
        // TODO: A real implementation with WebCrypto!!!
        const bytes = Array(n)
        for (let i = 0; i < n; ++i) {
            bytes[i] = Math.floor(256 * Math.random())
        }
        return Uint8Array.from(bytes).buffer.slice(0)
    }

    createKeyPair(privKey?: ArrayBuffer): Promise<KeyPairType> {
        if (!privKey) {
            privKey = Crypto.getRandomBytes(32)
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
