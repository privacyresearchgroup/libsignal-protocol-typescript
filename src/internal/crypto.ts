export class Crypto {
    static getRandomBytes(n: number): ArrayBuffer {
        // TODO: A real implementation with WebCrypto!!!
        const bytes = Array(n)
        for (let i = 0; i < n; ++i) {
            bytes[i] = Math.floor(256 * Math.random())
        }
        return Uint8Array.from(bytes).buffer.slice(0)
    }
}
