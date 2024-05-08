const { ripemd160 } = require("@noble/hashes/ripemd160"); // Faster than the function in "crypto"
const secp256k1 = new (require('node-gyp-build')("./lib/secp256k1").Secp256k1)(); // Faster than the function in "crypto"
const sha256 = require("./sha256.js"); // Faster than the function in "crypto"

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE58_ALPHABET_LENGTH = BASE58_ALPHABET.length;
const BASE58_LEADER = BASE58_ALPHABET.charAt(0);
const BASE58_IFACTOR = Math.log(256) / Math.log(BASE58_ALPHABET_LENGTH);

const BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

const BUFFER_0 = Buffer.from([0]);
const BUFFER_5 = Buffer.from([5]);

function init(numBits) {
    return secp256k1.publicKeyCreateInit(Uint32Array.from([numBits]));
}

function finish() {
    secp256k1.publicKeyCreateFinish();
}

function getAddressArray(privateKeyArray, batchSize) {
    let addressArray = [];

    publicKeyCArray = _secp256k1c(privateKeyArray, batchSize);
    publicKeyUArray = _secp256k1u(privateKeyArray, batchSize);

    for(let i = 0; i < batchSize; i++) {
        // COMMON
        const offsetC = 33 * i;
        const offsetU = 65 * i;
        const publicKeyC = publicKeyCArray.slice(offsetC, offsetC + 33);
        const publicKeyU = publicKeyUArray.slice(offsetU, offsetU + 65);
        const hashC = _ripemd160(_sha256(publicKeyC));
        const hashU = _ripemd160(_sha256(publicKeyU));

        // Bech32(c)
        const words = toWordsBech32(hashC);
        words.unshift(0x00);
        const addressBech32c = encodeBech32(words);
        addressArray.push(addressBech32c);

        // P2PKH(c)
        const payloadC = Buffer.concat([BUFFER_0, hashC])
        const checksumC = _sha256(_sha256(payloadC));
        const addressP2PKHc = encodeBase58(Buffer.concat([payloadC, checksumC], payloadC.length + 4));
        addressArray.push(addressP2PKHc);

        // P2PKH(u)
        const payloadU = Buffer.concat([BUFFER_0, hashU])
        const checksumU = _sha256(_sha256(payloadU));
        const addressP2PKHu = encodeBase58(Buffer.concat([payloadU, checksumU], payloadU.length + 4));
        addressArray.push(addressP2PKHu);

        // P2SH(c)
        const output = Buffer.concat([BUFFER_0, Buffer.from([hashC.length]), hashC]);
        const output_hash = _ripemd160(_sha256(output));
        const output_payload = Buffer.concat([BUFFER_5, output_hash])
        const output_checksum = _sha256(_sha256(output_payload));
        const addressP2SHc = encodeBase58(Buffer.concat([output_payload, output_checksum], output_payload.length + 4));
        addressArray.push(addressP2SHc);
    }

    return addressArray;
}

function getTypeArray() {
    // Returns the type of addresses returned by "getAddressArray"
    return ["Bech32(c)", "P2PKH(c)", "P2PKH(u)", "P2SH(c)"];
}

function _ripemd160(buffer) {
    return ripemd160(buffer);
}

function _secp256k1c(buffer, batchSize) {
    let output = new Uint8Array(batchSize * 33);
    secp256k1.publicKeyCreateFastBatch(output, buffer, Uint32Array.from([1]), Uint32Array.from([batchSize]));
    return output;
}

function _secp256k1u(buffer, batchSize) {
    let output = new Uint8Array(batchSize * 65);
    secp256k1.publicKeyCreateFastBatch(output, buffer, Uint32Array.from([0]), Uint32Array.from([batchSize]));
    return output;
}

function _sha256(buffer) {
    return sha256(buffer);
}

function encodeBase58(source) {
    // Skip & count leading zeroes.
    var zeroes = 0
    var length = 0
    var pbegin = 0
    var pend = source.length

    while (pbegin !== pend && source[pbegin] === 0) {
        pbegin++
        zeroes++
    }

    // Allocate enough space in big-endian base58 representation.
    var size = ((pend - pbegin) * BASE58_IFACTOR + 1) >>> 0
    var b58 = new Uint8Array(size)

    // Process the bytes.
    while (pbegin !== pend) {
        var carry = source[pbegin]
        // Apply "b58 = b58 * 256 + ch".
        var i = 0
        for (var it1 = size - 1; (carry !== 0 || i < length) && (it1 !== -1); it1--, i++) {
        carry += (256 * b58[it1]) >>> 0
        b58[it1] = (carry % BASE58_ALPHABET_LENGTH) >>> 0
        carry = (carry / BASE58_ALPHABET_LENGTH) >>> 0
        }
        if (carry !== 0) { throw new Error('Non-zero carry') }
        length = i
        pbegin++
    }

    // Skip leading zeroes in base58 result.
    var it2 = size - length
    while (it2 !== size && b58[it2] === 0) {
        it2++
    }

    // Translate the result into a string.
    var str = BASE58_LEADER.repeat(zeroes)
    for (; it2 < size; ++it2) {
        str += BASE58_ALPHABET.charAt(b58[it2])
    }
    return str
}

function toWordsBech32(bytes) {
    const inBits = 8;
    const outBits = 5;
    const maxV = 31;
    const result = [];

    let value = 0;
    let bits = 0;
    for (let i = 0; i < bytes.length; ++i) {
        value = (value << inBits) | bytes[i];
        bits += inBits;
        while (bits >= outBits) {
            bits -= outBits;
            result.push((value >> bits) & maxV);
        }
    }
    if (bits > 0) {
        result.push((value << (outBits - bits)) & maxV);
    }
    return result;
}

function encodeBech32(words) {
    let chk = 36798531;
    let result = "bc1";
    for (let i = 0; i < words.length; ++i) {
        const x = words[i];
        chk = polymodStep(chk) ^ x;
        result += BECH32_ALPHABET.charAt(x);
    }
    for (let i = 0; i < 6; ++i) {
        chk = polymodStep(chk);
    }
    chk ^= 1;
    for (let i = 0; i < 6; ++i) {
        const v = (chk >> ((5 - i) * 5)) & 0x1f;
        result += BECH32_ALPHABET.charAt(v);
    }
    return result;
}

function polymodStep(pre) {
    const b = pre >> 25;
    return (((pre & 0x1ffffff) << 5) ^
        (-((b >> 0) & 1) & 0x3b6a57b2) ^
        (-((b >> 1) & 1) & 0x26508e6d) ^
        (-((b >> 2) & 1) & 0x1ea119fa) ^
        (-((b >> 3) & 1) & 0x3d4233dd) ^
        (-((b >> 4) & 1) & 0x2a1462b3));
}

module.exports.init = init;
module.exports.finish = finish;
module.exports.getAddressArray = getAddressArray;
module.exports.getTypeArray = getTypeArray;