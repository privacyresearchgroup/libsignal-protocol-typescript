export function arrayBufferToString(b: ArrayBuffer): string {
    return uint8ArrayToString(new Uint8Array(b))
}

export function uint8ArrayToString(arr: Uint8Array): string {
    const end = arr.length
    let begin = 0
    if (begin === end) return ''
    let chars: number[] = []
    const parts: string[] = []
    while (begin < end) {
        chars.push(arr[begin++])
        if (chars.length >= 1024) {
            parts.push(String.fromCharCode(...chars))
            chars = []
        }
    }
    return parts.join('') + String.fromCharCode(...chars)
}
export function binaryStringToArrayBuffer(str: string): ArrayBuffer {
    let i = 0
    const k = str.length
    let charCode
    const bb: number[] = []
    while (i < k) {
        charCode = str.charCodeAt(i)
        if (charCode > 0xff) throw RangeError('illegal char code: ' + charCode)
        bb[i++] = charCode
    }
    return Uint8Array.from(bb).buffer
}

export function isEqual(a: ArrayBuffer | undefined, b: ArrayBuffer | undefined): boolean {
    // TODO: Special-case arraybuffers, etc
    if (a === undefined || b === undefined) {
        return false
    }
    const a1: string = arrayBufferToString(a)
    const b1: string = arrayBufferToString(b)
    const maxLength = Math.max(a1.length, b1.length)
    if (maxLength < 5) {
        throw new Error('a/b compare too short')
    }
    return a1.substring(0, Math.min(maxLength, a1.length)) == b1.substring(0, Math.min(maxLength, b1.length))
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
