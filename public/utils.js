// const {PythonShell} = require('python-shell');
const base64url = require('base64url');
const fs = require('fs');
const crypto = require('crypto');
const cbor = require('./js/cbor');
const coreUtils = require('./js/coreUtils');

class AttrNode {
    constructor(value) {
        this.right = null;
        this.left = null;
        this.attribute = value;
    }

    printNode() {
        console.log("Attribute:", this.attribute);
        if (this.right != null) {
            this.right.printNode();
        }
        if (this.left != null) {
            this.left.printNode();
        }
    }
};

exports.writeKeyFile = function(filename,data) {
    try {
        fs.writeFileSync(filename,data,{flag:'w'});
        // console.log(filename+",writeEnd");
    } catch(e) {
        console.log(e);
    }
};

exports.readKeyFile = function(filename) {
    try {
        var data = fs.readFileSync(filename,'utf-8');
        // console.log(filename+',readEnd');
        return data
    } catch(e) {
        console.log(e);
        return e
    }
};

exports.config = {
    challengesize: 64,
    coseId: -50,
    timeout: 60000,
    attestation: "direct",
    FIDO_RP_NAME: "FIDO2 ABS Server",
    FIDO_RPID: "https://localhost:3000",
    FIDO_ORIGIN: "https://localhost:3000",
    authenticatorUserVerification: "require"
};

exports.toArrayBuffer = function(buf,name) {
    if (!name) {
        throw new TypeError("name not specified in toArrayBuffer");
    }

    if (typeof buf == "string") {
        // base64url to base64
        buf = buf.replace(/-/g,"+").replace(/_/g,"/");
        // base64 to Buffer
        buf = Buffer.from(buf,"base64");
    }

    // Buffer or Array to Uint8Array
    if (buf instanceof Buffer || Array.isArray(buf)) {
        buf = new Uint8Array(buf);
    }

    // Uint8Array to ArrayBuffer
    if (buf instanceof Uint8Array) {
        buf = buf.buffer;
    }

    // error if none of the above worked
    if (!(buf instanceof ArrayBuffer)) {
        throw new TypeError(`could not coerce '${name}' to ArrayBuffer`);
    }

    return buf;
};

exports.setOpt = function(obj,prop,val) {
    if (val !== undefined) {
        obj[prop] = val;
    }
};

exports.console_check = function(name,obj) {
    console.log(name);
    console.log(obj);
};

exports.strToBuffer = function(src) {
    return (new Uint8Array([].map.call(src, function(c) {
      return c.charCodeAt(0)
    }))).buffer;
};

exports.bufToStr = function(buf) {
    return String.fromCharCode.apply("", new Uint8Array(buf))
};

exports.parse = function(buf,name) {
    var param = {};
    var position = 0;
    var byteLength = {
        rpIdHash: 32,
        flags: 1,
        counter: 4
    };
    var attestation_byteLength = {
        aaguid: 16,
        credentialIdLength: 2
    };
    if (!(typeof name == 'string')) {
        throw new TypeError("name not specified in parse");
    }

    var lastPosition = buf.byteLength;
    /* ??????????????????????????? */
    for (key in byteLength) {
        parseObject = parseByteLength(buf,key,position,byteLength);
        param[key] = parseObject;
        position += byteLength[key];
    }
    if (name == "attestation") { /* AttestedCredentialData?????????????????????????????? */
        for (key in attestation_byteLength) {
            parseObject = parseByteLength(buf,key,position,attestation_byteLength);
            param[key] = parseObject;
            position += attestation_byteLength[key];
        }
        var credentialIdLength = Buffer.from(new Uint8Array(param.credentialIdLength));
        byteLength['credentialId'] = credentialIdLength.readUInt16BE(0,false);
        param['credentialId'] = buf.slice(position,position+byteLength.credentialId);
        position += byteLength.credentialId;
        param['credentialPublicKey'] = buf.slice(position,lastPosition);
        position += param.credentialPublicKey.byteLength;
    }
    if (position == lastPosition) {
        // console.log('???????????????!');
        return param;
    } else {
        // console.error('???????????????...');
        return false;
    }
};

function parseByteLength(buf,key,position,byteLength) {
    var parseObject = buf.slice(position,position+byteLength[key]);
    if(parseObject.byteLength == byteLength[key]) {
        return parseObject;
    } else {
        console.error('parser error : ' + key);
    }
};

exports.parseJSON = function(json) {
    json = base64url.toBuffer(json);
    json = this.bufToStr(json);
    json = JSON.parse(json);
    return json;
}

exports.parsePublicKey = function(publicKey) {
    // this.console_check('publicKey',publicKey);
    var keylist = publicKey.split('}{');
    // this.console_check('keylist',keylist);
    var tpk = keylist[0] + '}';
    // this.console_check('tpk',tpk);
    var apk = '{' + keylist[1];
    // this.console_check('apk',apk);
    var param = {
        tpk: tpk,
        apk: apk
    };
    return param;
};

exports.validationSignature = function(tpk,apk,sig,message,policy) {
    var attributes = ["USER", "PARENTS", "GUARDIANSHIP", "A"];
    var r = new coreUtils.ctx.BIG(0);
    r.rcopy(coreUtils.ctx.ROM_CURVE.CURVE_Order);
    var msp = getMSP(policy, attributes);

    // ????????????????????????
    var signature = base64url.toBuffer(sig);
    signature = cbor.decodeCBOR(signature);
    signature.Y = base64url.toBuffer(signature.Y);
    signature.Y = coreUtils.ctx.ECP.fromBytes(signature.Y);
    signature.W = base64url.toBuffer(signature.W);
    signature.W = coreUtils.ctx.ECP.fromBytes(signature.W);
    for (var i=0; i<msp.length; i++) { /* S????????????????????? */
        signature["S"+String(i+1)] = base64url.toBuffer(signature["S"+String(i+1)]);
        signature["S"+String(i+1)] = coreUtils.ctx.ECP.fromBytes(signature["S"+String(i+1)]);
    }
    for (var j=0; j<msp[0].length; j++) { /* P????????????????????? */
        signature["P"+String(j+1)] = base64url.toBuffer(signature["P"+String(j+1)]);
        signature["P"+String(j+1)] = coreUtils.ctx.ECP2.fromBytes(signature["P"+String(j+1)]);
    }

    /* ----------??????????????????---------- */
    // e(W, A0) =? e(Y, h0)
    // var eWA0 = coreUtils.ctx.PAIR.initmp();
    var eWA0 = new coreUtils.ctx.FP12();
    eWA0 = coreUtils.ctx.PAIR.ate(apk.A0, signature.W);
    eWA0 = coreUtils.ctx.PAIR.fexp(eWA0);
    // var eYh0 = coreUtils.ctx.PAIR.initmp();
    var eYh0 = new coreUtils.ctx.FP12();
    eYh0 = coreUtils.ctx.PAIR.ate(tpk.h0, signature.Y);
    eYh0 = coreUtils.ctx.PAIR.fexp(eYh0);
    // console.log('e(W, A0) =? e(Y, h0):',eWA0.equals(eYh0)); /* ??????????????? */
    if (!eWA0.equals(eYh0)) {
        console.log('e(W, A0) =? e(Y, h0):',eWA0.equals(eYh0));
        return false;
    }

    // \prod i=1~l e(Si, (Aj+Bj^ui)^Mij) ?= e(Y,h1)e(Cg^??, P1) (j=1), e(Cg^??, Pj) (j???1)
    for (var j=1; j<msp[0].length+1; j++) {
        var multi;
        for (var i=1; i<msp.length+1; i++) {
            var ui = new coreUtils.ctx.BIG(i+1);
            var Mij = new coreUtils.ctx.BIG(msp[i-1][j-1]);
            var AjBj = coreUtils.ctx.PAIR.G2mul(apk["B"+String(j)], ui);
            AjBj.add(apk["A"+String(j)]);
            AjBj = coreUtils.ctx.PAIR.G2mul(AjBj, Mij);
            var eSiAjBj = coreUtils.ctx.PAIR.ate(AjBj, signature["S"+String(i)]);
            if (i==1) {
                multi = eSiAjBj;
            } else {
                multi.mul(eSiAjBj);
            }
        }
        multi = coreUtils.ctx.PAIR.fexp(multi);

        // e(C+g^??, Pj)
        var mu = coreUtils.createHash(message);
        mu.mod(r);
        var Cg = coreUtils.ctx.PAIR.G1mul(tpk["g"], mu);
        Cg.add(apk["C"]);
        var eCgPj = coreUtils.ctx.PAIR.ate(signature["P"+String(j)], Cg);
        if (j == 1) {
            var eYh1 = coreUtils.ctx.PAIR.ate(tpk["h1"], signature["Y"]);
            eCgPj.mul(eYh1);
        } else {
            // NOT IMPLEMENTED!
        }
        eCgPj = coreUtils.ctx.PAIR.fexp(eCgPj);

        // console.log("\prof i=1~l e(Si, (AjBj^ui)^Mij) =? e(Y, h1)e(Cg^??), P1)", multi.equals(eCgPj));
        if (!multi.equals(eCgPj)) {
            console.log("\prof i=1~l e(Si, (AjBj^ui)^Mij) =? e(Y, h1)e(Cg^??), P1)", multi.equals(eCgPj));
            return false;
        }
    }

    return true;
};

/**
 * @brief monotone span program???????????????
 * @param {String} policy - ?????????????????? 
 * @param {Array(String)} attributes - ????????????
 * @returns msp - monotone span program?????????
 */
function getMSP(policy, attributes) {
    var u = {};
    counter = 0;

    attributes.forEach(function(attribute) {
        u[counter] = attribute;
        u[attribute] = counter;
        counter++;
    });

    policy = remove_space(policy);
    var root = new AttrNode(policy);

    if (parse_expression(root) < 0) {
        console.error("error");
        return ;
    }

    matrix = [];
    for (var i=0; i<attributes.length; i++) {
        matrix.push([]);
    }

    counter = [1];
    function recursivefill(node, vector) {
        if (node.attribute == "|") {
            recursivefill(node.left, vector);
            recursivefill(node.right, vector);
        } else if (node.attribute == "&") {
            /* TODO: AND?????? */
        } else {
            var attribute = node.attribute;
            matrix[u[attribute]] = vector;
        }
    }
    recursivefill(root, [1]);

    matrix.forEach(function(i) {
        while(i.length < counter[0]) {
            i.push(0);
        }
    });
    return matrix;
};

/**
 * @param ????????????????????????????????????????????????
 * @param {String} exp ?????????
 * @returns exp - ????????????????????????????????????????????????
 */
function remove_space(exp) {
    exp = exp.split(' ');
    exp = exp.join('');
    return exp;
}

/**
 * @brief ??????????????????????????????????????????????????????
 * @param {String} exp ?????????
 * @returns index - ????????????index
 */
function get_pos_operator(exp) {
    if (exp.lastIndexOf('|') > 0) {
        return exp.lastIndexOf('|');
    } else if (exp.lastIndexOf('&') > 0) {
        return exp.lastIndexOf('&');
    } else {
        return -1;
    }
}

/**
 * @brief ??????????????????????????????
 * @param {AttrNode} node 
 * @returns  ?????????????????????
 */
function parse_expression(node) {
    var pos_operator = get_pos_operator(node.attribute);
    if (pos_operator == -1) {
        node.left = null;
        node.right = null;
        return 0;
    }

    var len = node.attribute.length;

    if (pos_operator == 0 || (len-1) == pos_operator) {
        return -1;
    }

    node.left = new AttrNode();
    node.right = new AttrNode();

    /**
     * ????????????????????????
     */
    node.left.attribute = node.attribute.substring(0, pos_operator);
    if (parse_expression(node.left) < 0) {
        return -1;
    }

    /**
     * ????????????????????????
     */
    node.right.attribute = node.attribute.substring(pos_operator+1, len);
    if (parse_expression(node.right) < 0) {
        return -1;
    }

    /**
     * ??????????????????
     */
    node.attribute = node.attribute.substring(pos_operator, pos_operator+1);
    return 1;
}

exports.createPolicy = function(attributes) {
    var attr_list = attributes.split(',');
    var policy = attr_list[0];
    attr_list.shift();
    for (i in attr_list) {
        policy += ' AND '+ attr_list[i];
    }
    return policy
}

exports.concatenation = function(f_segment,b_segment) {
    var sumLength = 0;
    sumLength += f_segment.byteLength;
    sumLength += b_segment.byteLength;
    var whole = new Uint8Array(sumLength);
    var pos = 0;
    whole.set(new Uint8Array(f_segment),pos);
    pos += f_segment.byteLength;
    whole.set(new Uint8Array(b_segment),pos);
    return whole.buffer;
}

exports.generateSha256 = function(data) {
    var sha256 = crypto.createHash('sha256');
    sha256.update(data);
    var encodedData = sha256.digest();
    return encodedData;
}

exports.generateClientDataHash = function(clientDataJSON) {
    var clientDataHash = JSON.stringify(clientDataJSON);
    clientDataHash = this.strToBuffer(clientDataHash);
    clientDataHash = this.generateSha256(Buffer.from(clientDataHash));
    return clientDataHash;
}