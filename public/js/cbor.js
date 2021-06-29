const cbor = require('cbor');

/**
 * CBORエンコードした値を返す
 * @param {*} value 
 * @returns CBORエンコードした値
 */
exports.encodeCBOR = function(value) {
    var encodeObject = cbor.encode(value);
    return encodeObject;
}

exports.decodeCBOR = function(encoded_cbor) {
    var decodeObject = cbor.decode(encoded_cbor);
    return decodeObject;
}