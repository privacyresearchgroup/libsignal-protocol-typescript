import { KeyPairType } from '../types'
import { Curve25519Wrapper, AsyncCurve25519Wrapper } from '@rolfe/curve25519-typescript'

export class Curve {
    // Curve 25519 crypto
    private _curve25519: Curve25519Wrapper
    async: AsyncCurve
    constructor(curve25519: Curve25519Wrapper) {
        this._curve25519 = curve25519
        this.async = new AsyncCurve()
    }

    createKeyPair(privKey: ArrayBuffer): KeyPairType {
        validatePrivKey(privKey)
        const raw_keys = this._curve25519.keyPair(privKey)
        return processKeys(raw_keys)
    }

    ECDHE(pubKey: ArrayBuffer, privKey: ArrayBuffer): ArrayBuffer {
        pubKey = validatePubKeyFormat(pubKey)
        validatePrivKey(privKey)

        if (pubKey === undefined || pubKey.byteLength != 32) {
            throw new Error('Invalid public key')
        }

        return this._curve25519.sharedSecret(pubKey, privKey)
    }

    Ed25519Sign(privKey: ArrayBuffer, message: ArrayBuffer): ArrayBuffer {
        validatePrivKey(privKey)

        if (message === undefined) {
            throw new Error('Invalid message')
        }

        return this._curve25519.sign(privKey, message)
    }

    Ed25519Verify(pubKey: ArrayBuffer, msg: ArrayBuffer, sig: ArrayBuffer): boolean {
        pubKey = validatePubKeyFormat(pubKey)

        if (pubKey === undefined || pubKey.byteLength != 32) {
            throw new Error('Invalid public key')
        }

        if (msg === undefined) {
            throw new Error('Invalid message')
        }

        if (sig === undefined || sig.byteLength != 64) {
            throw new Error('Invalid signature')
        }

        return this._curve25519.verify(pubKey, msg, sig)
    }
}

export class AsyncCurve {
    private _curve25519: AsyncCurve25519Wrapper
    constructor() {
        this._curve25519 = new AsyncCurve25519Wrapper()
    }

    async createKeyPair(privKey: ArrayBuffer): Promise<KeyPairType> {
        validatePrivKey(privKey)
        const raw_keys = await this._curve25519.keyPair(privKey)
        return processKeys(raw_keys)
    }

    ECDHE(pubKey: ArrayBuffer, privKey: ArrayBuffer): Promise<ArrayBuffer> {
        pubKey = validatePubKeyFormat(pubKey)
        validatePrivKey(privKey)

        if (pubKey === undefined || pubKey.byteLength != 32) {
            throw new Error('Invalid public key')
        }

        return this._curve25519.sharedSecret(pubKey, privKey)
    }

    Ed25519Sign(privKey: ArrayBuffer, message: ArrayBuffer): Promise<ArrayBuffer> {
        validatePrivKey(privKey)

        if (message === undefined) {
            throw new Error('Invalid message')
        }

        return this._curve25519.sign(privKey, message)
    }

    Ed25519Verify(pubKey: ArrayBuffer, msg: ArrayBuffer, sig: ArrayBuffer): Promise<boolean> {
        pubKey = validatePubKeyFormat(pubKey)

        if (pubKey === undefined || pubKey.byteLength != 32) {
            throw new Error('Invalid public key')
        }

        if (msg === undefined) {
            throw new Error('Invalid message')
        }

        if (sig === undefined || sig.byteLength != 64) {
            throw new Error('Invalid signature')
        }

        return this._curve25519.verify(pubKey, msg, sig)
    }
}

function validatePrivKey(privKey: unknown): void {
    if (privKey === undefined || !(privKey instanceof ArrayBuffer) || privKey.byteLength != 32) {
        throw new Error('Invalid private key')
    }
}
function validatePubKeyFormat(pubKey: ArrayBuffer): ArrayBuffer {
    if (
        pubKey === undefined ||
        ((pubKey.byteLength != 33 || new Uint8Array(pubKey)[0] != 5) && pubKey.byteLength != 32)
    ) {
        throw new Error('Invalid public key')
    }
    if (pubKey.byteLength == 33) {
        return pubKey.slice(1)
    } else {
        console.error(
            'WARNING: Expected pubkey of length 33, please report the ST and client that generated the pubkey'
        )
        return pubKey
    }
}

function processKeys(raw_keys: KeyPairType): KeyPairType {
    // prepend version byte
    const origPub = new Uint8Array(raw_keys.pubKey)
    const pub = new Uint8Array(33)
    pub.set(origPub, 1)
    pub[0] = 5

    return { pubKey: pub.buffer, privKey: raw_keys.privKey }
}
