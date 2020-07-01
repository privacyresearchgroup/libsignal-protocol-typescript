import { FingerprintGeneratorType } from './'
import ByteBuffer from 'bytebuffer'
var msrcrypto = require('../lib/msrcrypto')

export class FingerprintGenerator implements FingerprintGeneratorType {
    VERSION = 0

    createFor(
        localIdentifier: string,
        localIdentityKey: ArrayBuffer,
        remoteIdentifier: string,
        remoteIdentityKey: ArrayBuffer
    ): Promise<string> {
        return Promise.all([
            this.getDisplayStringFor(localIdentifier, localIdentityKey, this._iterations),
            this.getDisplayStringFor(remoteIdentifier, remoteIdentityKey, this._iterations),
        ]).then(function (fingerprints) {
            return fingerprints.sort().join('')
        })
    }

    private _iterations: number
    constructor(_iterations: number) {
        this._iterations = _iterations
    }

    async iterateHash(data: ArrayBuffer, key: ArrayBuffer, count: number) {
        const data1 = ByteBuffer.concat([data, key]).toArrayBuffer()
        let result = await msrcrypto.subtle.digest({ name: 'SHA-512' }, data1)

        if (--count === 0) {
            return result
        } else {
            let r1 = new Uint8Array(result)
            return this.iterateHash(r1, key, count)
        }
    }

    getDisplayStringFor(identifier: string, key: ArrayBuffer, iterations: number) {
        const bb = ByteBuffer.concat([Uint8Array.from([0, 0]), key, identifier])
        const bytes = bb.toArrayBuffer()
        return this.iterateHash(bytes, key, iterations).then(function (output) {
            output = new Uint8Array(output)
            return (
                getEncodedChunk(output, 0) +
                getEncodedChunk(output, 5) +
                getEncodedChunk(output, 10) +
                getEncodedChunk(output, 15) +
                getEncodedChunk(output, 20) +
                getEncodedChunk(output, 25)
            )
        })
    }
}

function getEncodedChunk(hash, offset): string {
    var chunk =
        (hash[offset] * Math.pow(2, 32) +
            hash[offset + 1] * Math.pow(2, 24) +
            hash[offset + 2] * Math.pow(2, 16) +
            hash[offset + 3] * Math.pow(2, 8) +
            hash[offset + 4]) %
        100000
    var s = chunk.toString()
    while (s.length < 5) {
        s = '0' + s
    }
    return s
}
