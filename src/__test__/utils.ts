export function hexToArrayBuffer(str: string): ArrayBuffer {
    const ret = new ArrayBuffer(str.length / 2)
    const array = new Uint8Array(ret)
    for (let i = 0; i < str.length / 2; i++) array[i] = parseInt(str.substr(i * 2, 2), 16)
    return ret
}

export function assertEqualArrayBuffers(ab1: ArrayBuffer, ab2: ArrayBuffer): void {
    const a1 = new Uint8Array(ab1)
    const a2 = new Uint8Array(ab2)
    expect(a1.length).toBe(a2.length)
    for (let i = 0; i < a1.length; ++i) {
        expect(a1[i]).toBe(a2[i])
    }
}
