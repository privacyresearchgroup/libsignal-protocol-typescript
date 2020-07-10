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
export function isEqual(a: ArrayBuffer | undefined, b: ArrayBuffer | undefined): Boolean {
    // TODO: Special-case arraybuffers, etc
    if (a === undefined || b === undefined) {
        return false
    }
    const a1: String = <String>toString(a)
    const b1: String = <String>toString(b)
    var maxLength = Math.max(a1.length, b1.length)
    if (maxLength < 5) {
        throw new Error('a/b compare too short')
    }
    return a1.substring(0, Math.min(maxLength, a1.length)) == b1.substring(0, Math.min(maxLength, b1.length))
}
