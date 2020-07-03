/*
import ByteBuffer from 'bytebuffer'

var util = (function () {
    var StaticArrayBufferProto = new ArrayBuffer([]).__proto__

    return {
        toString: function (thing) {
            if (typeof thing == 'string') {
                return thing
            }
            return ByteBuffer.wrap(thing).toString('binary')
        },
        toArrayBuffer: function (thing) {
            if (thing === undefined) {
                return undefined
            }
            if (thing === Object(thing)) {
                if (thing.__proto__ == StaticArrayBufferProto) {
                    return thing
                }
            }

            var str
            if (typeof thing == 'string') {
                str = thing
            } else {
                throw new Error('Tried to convert a non-string of type ' + typeof thing + ' to an array buffer')
            }
            return ByteBuffer.wrap(thing, 'binary').toArrayBuffer()
        },
        isEqual: function (a, b) {
            // TODO: Special-case arraybuffers, etc
            if (a === undefined || b === undefined) {
                return false
            }
            a = util.toString(a)
            b = util.toString(b)
            var maxLength = Math.max(a.length, b.length)
            if (maxLength < 5) {
                throw new Error('a/b compare too short')
            }
            return a.substring(0, Math.min(maxLength, a.length)) == b.substring(0, Math.min(maxLength, b.length))
        },
    }
})()
*/
