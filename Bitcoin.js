const crypto = require("crypto");

const wordlist = require("./wordlist.js");

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE58_ALPHABET_LENGTH = BASE58_ALPHABET.length;
const BASE58_LEADER = BASE58_ALPHABET.charAt(0);
const BASE58_IFACTOR = Math.log(256) / Math.log(BASE58_ALPHABET_LENGTH);

const BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_ENCODING_CONST = 1;

const BUFFER_0 = Buffer.from([0]);
const BUFFER_1 = Buffer.from([1]);
const BUFFER_5 = Buffer.from([5]);
const BUFFER_118 = Buffer.from([118]);
const BUFFER_128 = Buffer.from([128]);
const BUFFER_135 = Buffer.from([135]);
const BUFFER_136 = Buffer.from([136]);
const BUFFER_169 = Buffer.from([169]);
const BUFFER_172 = Buffer.from([172]);

class Bitcoin {
    privateKey;

    static displayAll(privateKey) {
        const bitcoin = new Bitcoin(privateKey);

        console.log("privateKey");
        console.log("    " + privateKey.toString("hex"));

        console.log("publicKey(c)");
        console.log("    " + bitcoin.getPublicKeyc());
        console.log("publicKey(u)");
        console.log("    " + bitcoin.getPublicKeyu());

        console.log("WIF(c)");
        console.log("    " + bitcoin.getWIFc());
        console.log("WIF(u)");
        console.log("    " + bitcoin.getWIFu());
        console.log("Bech32(c)");
        console.log("    " + bitcoin.getBech32c());
        console.log("Bech32(u)");
        console.log("    " + bitcoin.getBech32u());
        console.log("P2PKH(c)");
        console.log("    " + bitcoin.getP2PKHc());
        console.log("P2PKH(u)");
        console.log("    " + bitcoin.getP2PKHu());
        console.log("P2SH(c)");
        console.log("    " + bitcoin.getP2SHc());
        console.log("P2SH(u)");
        console.log("    " + bitcoin.getP2SHu());

        console.log("Bech32(c) Script Hash");
        console.log("    " + bitcoin.getBech32cScriptHash());
        console.log("Bech32(u) Script Hash");
        console.log("    " + bitcoin.getBech32uScriptHash());
        console.log("P2PKH(c) Script Hash");
        console.log("    " + bitcoin.getP2PKHcScriptHash());
        console.log("P2PKH(u) Script Hash");
        console.log("    " + bitcoin.getP2PKHuScriptHash());
        console.log("P2SH(c) Script Hash");
        console.log("    " + bitcoin.getP2SHcScriptHash());
        console.log("P2SH(u) Script Hash");
        console.log("    " + bitcoin.getP2SHuScriptHash());

        console.log("BIP39 Words");
        console.log("    " + bitcoin.getBIP39());
    }

    constructor(privateKey) {
        this.privateKey = privateKey;
    }

    getPublicKeyc() {
        let publicKey = _secp256k1(this.privateKey, true);
        return publicKey.toString("hex");
    }

    getPublicKeyu() {
        let publicKey = _secp256k1(this.privateKey, false);
        return publicKey.toString("hex");
    }

    getWIFc() {
        let payload = Buffer.concat([BUFFER_128, this.privateKey, BUFFER_1]);
        let checksum = _sha256(_sha256(payload));
        let address = encodeBase58(Buffer.concat([payload, checksum], payload.length + 4));
        return address;
    }

    getWIFu() {
        let payload = Buffer.concat([BUFFER_128, this.privateKey]);
        let checksum = _sha256(_sha256(payload));
        let address = encodeBase58(Buffer.concat([payload, checksum], payload.length + 4));
        return address;
    }

    getBech32c() {
        let publicKey = _secp256k1(this.privateKey, true);
        let hash = _ripemd160(_sha256(publicKey));
        const words = toWordsBech32(hash);
        words.unshift(0x00);
        let address = encodeBech32("bc", words);
        return address;
    }

    getBech32u() {
        let publicKey = _secp256k1(this.privateKey, false);
        let hash = _ripemd160(_sha256(publicKey));
        const words = toWordsBech32(hash);
        words.unshift(0x00);
        let address = encodeBech32("bc", words);
        return address;
    }

    getP2PKHc() {
        let publicKey = _secp256k1(this.privateKey, true);
        let hash = _ripemd160(_sha256(publicKey));
        let payload = Buffer.concat([BUFFER_0, hash])
        let checksum = _sha256(_sha256(payload));
        let address = encodeBase58(Buffer.concat([payload, checksum], payload.length + 4));
        return address;
    }

    getP2PKHu() {
        let publicKey = _secp256k1(this.privateKey, false);
        let hash = _ripemd160(_sha256(publicKey));
        let payload = Buffer.concat([BUFFER_0, hash])
        let checksum = _sha256(_sha256(payload));
        let address = encodeBase58(Buffer.concat([payload, checksum], payload.length + 4));
        return address;
    }

    getP2SHc() {
        let _publicKey = _secp256k1(this.privateKey, true);
        let _hash = _ripemd160(_sha256(_publicKey));
        let output = Buffer.concat([BUFFER_0, Buffer.from([_hash.length]), _hash]);
        let hash = _ripemd160(_sha256(output));
        let payload = Buffer.concat([BUFFER_5, hash])
        let checksum = _sha256(_sha256(payload));
        let address = encodeBase58(Buffer.concat([payload, checksum], payload.length + 4));
        return address;
    }

    getP2SHu() {
        let _publicKey = _secp256k1(this.privateKey, false);
        let _hash = _ripemd160(_sha256(_publicKey));
        let output = Buffer.concat([BUFFER_0, Buffer.from([_hash.length]), _hash]);
        let hash = _ripemd160(_sha256(output));
        let payload = Buffer.concat([BUFFER_5, hash])
        let checksum = _sha256(_sha256(payload));
        let address = encodeBase58(Buffer.concat([payload, checksum], payload.length + 4));
        return address;
    }



    getBech32cScriptHash() {
        let publicKey = _secp256k1(this.privateKey, true);
        let hash = _ripemd160(_sha256(publicKey));
        let script = Buffer.concat([BUFFER_0, Buffer.from([hash.length]), hash]);
        let scriptHash = _sha256(script)
        scriptHash = scriptHash.reverse(); // Electrum wants this reversed
        let scriptHashHex = scriptHash.toString("hex");
        return scriptHashHex;
    }

    getBech32uScriptHash() {
        let publicKey = _secp256k1(this.privateKey, false);
        let hash = _ripemd160(_sha256(publicKey));
        let script = Buffer.concat([BUFFER_0, Buffer.from([hash.length]), hash]);
        let scriptHash = _sha256(script)
        scriptHash = scriptHash.reverse(); // Electrum wants this reversed
        let scriptHashHex = scriptHash.toString("hex");
        return scriptHashHex;
    }

    getP2PKHcScriptHash() {
        let publicKey = _secp256k1(this.privateKey, true);
        let hash = _ripemd160(_sha256(publicKey));
        let script = Buffer.concat([BUFFER_118, BUFFER_169, Buffer.from([hash.length]), hash, BUFFER_136, BUFFER_172]);
        let scriptHash = _sha256(script)
        scriptHash = scriptHash.reverse(); // Electrum wants this reversed
        let scriptHashHex = scriptHash.toString("hex");
        return scriptHashHex;
    }

    getP2PKHuScriptHash() {
        let publicKey = _secp256k1(this.privateKey, false);
        let hash = _ripemd160(_sha256(publicKey));
        let script = Buffer.concat([BUFFER_118, BUFFER_169, Buffer.from([hash.length]), hash, BUFFER_136, BUFFER_172]);
        let scriptHash = _sha256(script)
        scriptHash = scriptHash.reverse(); // Electrum wants this reversed
        let scriptHashHex = scriptHash.toString("hex");
        return scriptHashHex;
    }

    getP2SHcScriptHash() {
        let _publicKey = _secp256k1(this.privateKey, true);
        let _hash = _ripemd160(_sha256(_publicKey));
        let output = Buffer.concat([BUFFER_0, Buffer.from([_hash.length]), _hash]);
        let hash = _ripemd160(_sha256(output));
        let script = Buffer.concat([BUFFER_169, Buffer.from([hash.length]), hash, BUFFER_135]);
        let scriptHash = _sha256(script)
        scriptHash = scriptHash.reverse(); // Electrum wants this reversed
        let scriptHashHex = scriptHash.toString("hex");
        return scriptHashHex;
    }

    getP2SHuScriptHash() {
        let _publicKey = _secp256k1(this.privateKey, false);
        let _hash = _ripemd160(_sha256(_publicKey));
        let output = Buffer.concat([BUFFER_0, Buffer.from([_hash.length]), _hash]);
        let hash = _ripemd160(_sha256(output));
        let script = Buffer.concat([BUFFER_169, Buffer.from([hash.length]), hash, BUFFER_135]);
        let scriptHash = _sha256(script)
        scriptHash = scriptHash.reverse(); // Electrum wants this reversed
        let scriptHashHex = scriptHash.toString("hex");
        return scriptHashHex;
    }



    getBIP39() {
        let hash = _sha256(this.privateKey);
        let privateKeyChk = Buffer.concat([this.privateKey, hash], this.privateKey.length + 1);
        
        // Convert to binary string.
        let binaryString = "";
        for(let b of privateKeyChk) {
            binaryString += b.toString(2).padStart(8, "0");
        }

        let words = "";
        // Each of the 24 words will be 11 bytes
        for(let i = 0; i < 24; i++) {
            let binary = binaryString.substring(11 * i, 11 * (i + 1));
            let number = parseInt(binary, 2);
            words += wordlist[number] + " ";
        }

        return words;
    }
}

function _ripemd160(buffer) {
    return crypto.createHash("rmd160").update(buffer).digest();
}

function _secp256k1(buffer, isCompressed) {
    let ecdh = crypto.createECDH("secp256k1");
    ecdh.setPrivateKey(buffer);
    return ecdh.getPublicKey("", isCompressed ? "compressed" : "uncompressed");
}

function _sha256(buffer) {
    return crypto.createHash("sha256").update(buffer).digest();
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

function convertBech32(data, inBits, outBits, pad) {
    let value = 0;
    let bits = 0;
    const maxV = (1 << outBits) - 1;
    const result = [];
    for (let i = 0; i < data.length; ++i) {
        value = (value << inBits) | data[i];
        bits += inBits;
        while (bits >= outBits) {
            bits -= outBits;
            result.push((value >> bits) & maxV);
        }
    }
    if (pad) {
        if (bits > 0) {
            result.push((value << (outBits - bits)) & maxV);
        }
    }
    else {
        if (bits >= inBits)
            return 'Excess padding';
        if ((value << (outBits - bits)) & maxV)
            return 'Non-zero padding';
    }
    return result;
}

function toWordsBech32(bytes) {
    return convertBech32(bytes, 8, 5, true);
}

function encodeBech32(prefix, words, LIMIT) {
    LIMIT = LIMIT || 90;
    if (prefix.length + 7 + words.length > LIMIT)
        throw new TypeError('Exceeds length limit');
    prefix = prefix.toLowerCase();
    // determine chk mod
    let chk = prefixChkBech32(prefix);
    if (typeof chk === 'string')
        throw new Error(chk);
    let result = prefix + '1';
    for (let i = 0; i < words.length; ++i) {
        const x = words[i];
        if (x >> 5 !== 0)
            throw new Error('Non 5-bit word');
        chk = polymodStep(chk) ^ x;
        result += BECH32_ALPHABET.charAt(x);
    }
    for (let i = 0; i < 6; ++i) {
        chk = polymodStep(chk);
    }
    chk ^= BECH32_ENCODING_CONST;
    for (let i = 0; i < 6; ++i) {
        const v = (chk >> ((5 - i) * 5)) & 0x1f;
        result += BECH32_ALPHABET.charAt(v);
    }
    return result;
}

function prefixChkBech32(prefix) {
    let chk = 1;
    for (let i = 0; i < prefix.length; ++i) {
        const c = prefix.charCodeAt(i);
        if (c < 33 || c > 126)
            return 'Invalid prefix (' + prefix + ')';
        chk = polymodStep(chk) ^ (c >> 5);
    }
    chk = polymodStep(chk);
    for (let i = 0; i < prefix.length; ++i) {
        const v = prefix.charCodeAt(i);
        chk = polymodStep(chk) ^ (v & 0x1f);
    }
    return chk;
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

module.exports = Bitcoin;