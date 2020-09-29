import { FingerprintGeneratorType } from './'
import * as utils from './helpers'
// eslint-disable-next-line @typescript-eslint/no-var-requires
const msrcrypto = require('../lib/msrcrypto')

export class FingerprintGenerator implements FingerprintGeneratorType {
    static VERSION = 0

    async createFor(
        localIdentifier: string,
        localIdentityKey: ArrayBuffer,
        remoteIdentifier: string,
        remoteIdentityKey: ArrayBuffer
    ): Promise<string> {
        const localStr = await getDisplayStringFor(localIdentifier, localIdentityKey, this._iterations)
        const remoteStr = await getDisplayStringFor(remoteIdentifier, remoteIdentityKey, this._iterations)
        return [localStr, remoteStr].sort().join('')
    }

    private _iterations: number
    constructor(_iterations: number) {
        this._iterations = _iterations
    }
}

async function getDisplayStringFor(identifier: string, key: ArrayBuffer, iterations: number): Promise<string> {
    const bytes = concatArrayBuffers([
        shortToArrayBuffer(FingerprintGenerator.VERSION),
        key,
        utils.binaryStringToArrayBuffer(identifier),
    ])

    const hash = await iterateHash(bytes, key, iterations)
    const output = new Uint8Array(hash)
    return (
        getEncodedChunk(output, 0) +
        getEncodedChunk(output, 5) +
        getEncodedChunk(output, 10) +
        getEncodedChunk(output, 15) +
        getEncodedChunk(output, 20) +
        getEncodedChunk(output, 25)
    )
}

async function iterateHash(data: ArrayBuffer, key: ArrayBuffer, count: number): Promise<ArrayBuffer> {
    const data1 = concatArrayBuffers([data, key])
    const result = await msrcrypto.subtle.digest({ name: 'SHA-512' }, data1)

    if (--count === 0) {
        return result
    } else {
        return iterateHash(result, key, count)
    }
}

function getEncodedChunk(hash: Uint8Array, offset: number): string {
    const chunk =
        (hash[offset] * Math.pow(2, 32) +
            hash[offset + 1] * Math.pow(2, 24) +
            hash[offset + 2] * Math.pow(2, 16) +
            hash[offset + 3] * Math.pow(2, 8) +
            hash[offset + 4]) %
        100000
    let s = chunk.toString()
    while (s.length < 5) {
        s = '0' + s
    }
    return s
}

function shortToArrayBuffer(number) {
    return new Uint16Array([number]).buffer
}

function concatArrayBuffers(bufs: ArrayBuffer[]): ArrayBuffer {
    const lengths = bufs.map((b) => b.byteLength)
    const totalLength = lengths.reduce((p, c) => p + c, 0)
    const result = new Uint8Array(totalLength)
    lengths.reduce((p, c, i) => {
        result.set(new Uint8Array(bufs[i]), p)
        return p + c
    }, 0)

    return result.buffer
}
