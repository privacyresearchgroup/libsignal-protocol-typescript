import ByteBuffer from 'bytebuffer'

export type Stringable = string | ByteBuffer | ArrayBuffer | Buffer | Uint8Array | number | undefined
export function toString(thing: Stringable): string | undefined {
    if (typeof thing == 'string') {
        return thing
    } else if (typeof thing === 'number') {
        return `${thing}`
    }
    return thing && ByteBuffer.wrap(thing).toString('binary')
}

export function toArrayBuffer(thing: unknown): ArrayBuffer | undefined {
    if (thing === undefined) {
        return undefined
    }
    if (thing === Object(thing)) {
        if (thing instanceof ArrayBuffer) {
            return thing
        }
    }

    if (typeof thing !== 'string') {
        throw new Error('Tried to convert a non-string of type ' + typeof thing + ' to an array buffer')
    }
    return ByteBuffer.wrap(thing, 'binary').toArrayBuffer()
}

export function uint8ArrayToArrayBuffer(arr: Uint8Array): ArrayBuffer {
    return arr.buffer.slice(arr.byteOffset, arr.byteLength + arr.byteOffset)
}
/*
import ByteBuffer from 'bytebuffer'
export type Stringable = string | ByteBuffer | ArrayBuffer | Buffer | Uint8Array | number | undefined
export function toString(thing: Stringable): string | undefined {
    if (typeof thing == 'string') {
        return thing
    } else if (typeof thing === 'number') {
        return `${thing}`
    }
    return thing && ByteBuffer.wrap(thing).toString('binary')
}
export function toArrayBuffer(thing: unknown): ArrayBuffer | undefined {
    if (thing === undefined) {
        return undefined
    }
    if (thing === Object(thing)) {
        if (thing instanceof ArrayBuffer) {
            return thing
        }
    }
    if (typeof thing !== 'string') {
        throw new Error('Tried to convert a non-string of type ' + typeof thing + ' to an array buffer')
    }
    return ByteBuffer.wrap(thing, 'binary').toArrayBuffer()
}
*/
