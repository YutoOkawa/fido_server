const CTX = require('amcl-js').CTX;
const ctx = new CTX('BN254');
const utils = require('../utils');
const base64url = require('base64url');
const cbor = require('./cbor');

/**
 * ランダムなG1の要素を返す
 * @param {*} rng 乱数生成関数
 * 
 */
exports.generateG1Element = function(rng) {
    var seed = ctx.FP.rand(rng);
    var G = ctx.ECP.map2point(seed);
    return G;
}

/**
 * ランダムなG2の要素を返す
 * @param {*} rng 乱数生成関数
 */
exports.generateG2Element = function(rng) {
    var seed = ctx.FP2.rand(rng);
    var H = ctx.ECP2.map2point(seed);
    return H;
}

/**
 * 対象のオブジェクトに値を挿入する
 * @param {*} obj 対象オブジェクト
 * @param {*} prop key値
 * @param {*} val 挿入する値
 */
exports.setOpt = function(obj, prop, val) {
    if (val != undefined) {
        obj[prop] = val;
    } else {
        console.log("undefined");
    }
}

/**
 * 有限体をByte出力する
 * @param {*} G 
 */
exports.outputBytes = function(G) {
    var W = [];
    G.toBytes(W, true);
    console.log(W);
}

/**
 * 乱数生成関数を初期化する
 * @param {*} ctx core関数
 * @returns 乱数生成関数
 */
exports.initRng = function(ctx) {
    var RAW = [];
    var rng = new ctx.RAND();
    rng.clean();
    for (var i=0; i<100; i++) RAW[i] = i;
    rng.seed(100, RAW);
    return rng;
}

/**
 * 鍵をファイルに保存する
 * @param {*} key 鍵データ
 * @param {String} filepath 保存するファイルパス
 */
exports.writeKey = function(key, filepath) {
    for (let name in key) {
        if (name != 'atr') { /* 鍵情報の場合 */
            /* 鍵情報のエンコード */
            var keyByte = [];
            key[name].toBytes(keyByte, true);
            var data = Buffer.from(keyByte);
            data = base64url.encode(data);
            /* 鍵情報の分類 */
            if (key[name] instanceof ctx.ECP) {
                var checker = 'ECP';
            } else if (key[name] instanceof ctx.ECP2) {
                var checker = 'ECP2';
            } else if (key[name] instanceof ctx.BIG) {
                var checker = 'BIG';
            }
            /* 鍵情報の書き込み */
            utils.writeKeyFile(filepath, name+":"+data+":"+checker+"\n");
        } else { /* 属性情報の場合 */
            for (let attribute in key[name]) {
                utils.writeKeyFile(filepath, attribute+":"+key[name][attribute]+",");
            }
        }
    }
}

/**
 * ファイルから鍵情報を読み取る
 * @param {String} filepath 読み込むファイルパス 
 */
exports.readKey = function(filepath) {
    var key = {};
    var filedata = utils.readKeyFile(filepath);
    var keylines = filedata.split('\n');
    for (let line of keylines) {
        var keydata = line.split(':');
        if (keydata.length == 3) { /* 鍵データの場合 */
            if (keydata[2] == 'ECP') { /* ECPデータの場合 */
                var data = ctx.ECP.fromBytes(base64url.toBuffer(keydata[1]));
            } else if (keydata[2] == 'ECP2') { /* ECP2データの場合 */
                var data = ctx.ECP2.fromBytes(base64url.toBuffer(keydata[1]));
            } else if (keydata[2] == 'BIG') { /* BIGデータの場合 */
                var data = ctx.BIG.fromBytes(base64url.toBuffer(keydata[1]));
            } else {
                console.log('error Data:', keydata[1]);
            }
            var name = keydata[0];
            this.setOpt(key, name, data);
        } else { /* 属性データの場合 */
            var attributes = line.split(',');
            var attrblist = {};
            for (let attribute of attributes) { /* 属性データの分割 */
                if (attribute == '') break; /* 余白データの削除 */
                var attributeData = attribute.split(':');
                this.setOpt(attrblist, attributeData[0], Number(attributeData[1]));
            }
            this.setOpt(key, "atr", attrblist);
        }
    }
    return key;
}

/**
 * 鍵データを全てBufferに変換する
 * @param {*} key 鍵データ
 * @returns Buffer変換した鍵データ
 */
exports.KeyToBytes = function(key) {
    var keyBytes = {};
    for (let name in key) {
        if (name != 'atr') {
            var W = [];
            key[name].toBytes(W, true);
            this.setOpt(keyBytes, name, Buffer.from(W));
        } else {
            this.setOpt(keyBytes, name, key[name]);
        }
    }
    return keyBytes;
}

exports.BytesToKey = function(keyBytes) {
    var key = {}
    for (let name in keyBytes) {
        if (name != 'atr') {
            if (keyBytes[name].length == 33) {
                var elem = ctx.ECP.fromBytes(keyBytes[name]);
                if (ctx.PAIR.G1member(elem)) {
                    this.setOpt(key, name, elem);
                }
            } else if (keyBytes[name].length == 65) {
                var elem = ctx.ECP2.fromBytes(keyBytes[name]);
                if (ctx.PAIR.G2member(elem)) {
                    this.setOpt(key, name, elem);
                }
            }
        }
    }
    return key;
}

/**
 * 鍵データをCBORエンコードする
 * @param {*} key 鍵データ
 * @returns CBORエンコードされた鍵データ
 */
exports.KeyToCBOR = function(key) {
    var keyBytes = this.KeyToBytes(key);
    var encodeObject = cbor.encodeCBOR(keyBytes);
    return encodeObject;
}

exports.ctx = ctx;