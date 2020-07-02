import * as Internal from './internal'
import { KeyPairType } from './types'

export class Curve {
    private _curve: Internal.Curve
    async: AsyncCurve
    constructor(curve: Internal.Curve) {
        this._curve = curve
        this.async = new AsyncCurve(curve.async)
    }

    generateKeyPair(): KeyPairType {
        const privKey = Internal.Crypto.getRandomBytes(32)
        return this._curve.createKeyPair(privKey)
    }
    createKeyPair(privKey: ArrayBuffer): KeyPairType {
        return this._curve.createKeyPair(privKey)
    }
    calculateAgreement(pubKey: ArrayBuffer, privKey: ArrayBuffer): ArrayBuffer {
        return this._curve.ECDHE(pubKey, privKey)
    }
    verifySignature(pubKey: ArrayBuffer, msg: ArrayBuffer, sig: ArrayBuffer): boolean {
        return this._curve.Ed25519Verify(pubKey, msg, sig)
    }
    calculateSignature(privKey: ArrayBuffer, message: ArrayBuffer): ArrayBuffer {
        return this._curve.Ed25519Sign(privKey, message)
    }
}

export class AsyncCurve {
    private _curve: Internal.AsyncCurve
    constructor(curve: Internal.AsyncCurve) {
        this._curve = curve
    }

    generateKeyPair(): Promise<KeyPairType> {
        const privKey = Internal.Crypto.getRandomBytes(32)
        return this._curve.createKeyPair(privKey)
    }
    createKeyPair(privKey: ArrayBuffer): Promise<KeyPairType> {
        return this._curve.createKeyPair(privKey)
    }
    calculateAgreement(pubKey: ArrayBuffer, privKey: ArrayBuffer): Promise<ArrayBuffer> {
        return this._curve.ECDHE(pubKey, privKey)
    }
    verifySignature(pubKey: ArrayBuffer, msg: ArrayBuffer, sig: ArrayBuffer): Promise<void> {
        return this._curve.Ed25519Verify(pubKey, msg, sig)
    }
    calculateSignature(privKey: ArrayBuffer, message: ArrayBuffer): Promise<ArrayBuffer> {
        return this._curve.Ed25519Sign(privKey, message)
    }
}
