const express = require('express');
const base64url = require('base64url');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const fs = require('fs');
const router = express.Router();
const utils = require('../public/utils.js')
const cbor = require('../public/js/cbor');
router.use(bodyParser.json());

let database = {};

router.post('/options',async function(req,res) {
    console.time('/attestation/options')
    var registerOptions = {
        rp: {},
        user: {},
    };
    // console.log(req.body);
    let username = req.body.username;
    let attributes = req.body.attributes;
    var filepath = './public/DB/' + username + '.json';

    if (fs.existsSync(filepath)) {
        database[username] = utils.readKeyFile(filepath);
        if (database[username].attribute_table==undefined) {
            var attribute_table = []
        } else {
            var attribute_table = database[username].attribute_table;
        }
    } else {
        database[username] = {}
        var attribute_table = []
    }

    // useridの生成
    if (database[username].user == undefined) {
        var id = crypto.randomBytes(32);
        id = utils.toArrayBuffer(id, "id");
        id = await base64url.encode(id);
    } else {
        id = database[username].user.id;
    }

    // challengeの生成
    var challenge = crypto.randomBytes(utils.config.challengesize);
    challenge = utils.toArrayBuffer(challenge, "challenge");
    challenge = base64url.encode(challenge);

    //pibKeyCredParamsの生成
    var pubKeyCredParam = [];
    pubKeyCredParam.push({
        type: "Attribute Base Signature",
        alg: utils.config.coseId
    });

    // 各種値の設定
    utils.setOpt(registerOptions.rp,"name",utils.config.FIDO_RP_NAME);
    utils.setOpt(registerOptions.rp,"id",utils.config.FIDO_RPID);
    utils.setOpt(registerOptions.rp,"icon",utils.config.FIDO_RP_ICON);
    utils.setOpt(registerOptions.user,"id",id);
    utils.setOpt(registerOptions.user,"name",username);
    utils.setOpt(registerOptions.user,"displayName",username);
    utils.setOpt(registerOptions,"attributes",attributes);
    utils.setOpt(registerOptions,"challenge",challenge);
    utils.setOpt(registerOptions,"pubKeyCredParams",pubKeyCredParam);
    utils.setOpt(registerOptions,"timeout",utils.config.timeout);
    utils.setOpt(registerOptions,"attestation",utils.config.attestation);
    utils.setOpt(registerOptions,"status","ok");

    database[username] = {
        name: username,
        registered: true,
        id: id,
        attributes: attributes,
        attestation: [],
        challenge: registerOptions.challenge,
        attribute_table: attribute_table
    };

    // console.log(database[username]);
    // console.log(registerOptions);
    console.timeEnd('/attestation/options')
    res.send(registerOptions);
});

router.post('/result',async function(req,res) {
    console.time('/attestation/result');
    var complete = true;
    var attestation = req.body.attestation;
    var username = req.body.userid;
    
    /* clientDataHashの事前作成 */
    var sha256 = crypto.createHash('sha256');
    sha256.update(attestation.response.clientDataJSON);
    var sigClientDataJSON = sha256.digest();
    sigClientDataJSON = utils.toArrayBuffer(sigClientDataJSON,"clientDataJSON");

    /* clientDataJSONのパース */
    var clientDataJSON = utils.parseJSON(attestation.response.clientDataJSON);
    
    /* DBに存在しているかの確認 */
    if(database[username] != undefined) {
        var attestationExpectations = {
            challenge: database[username].challenge,
            origin: utils.config.FIDO_ORIGIN,
            rpid: utils.config.FIDO_RPID
        };
        // console.log(username+':登録を開始します.');
    } else {
        console.log('error');
        complete = false;
    }

    /* challengeの検証 */
    if (attestationExpectations.challenge == clientDataJSON.challenge) {
        // console.log(username+':challengeの検証成功!');
    } else {
        console.log(username+':challengeの検証失敗...');
        complete = false;
    }

    /* attestationのデコード(base64url -> CBOR -> json) */
    var attestationObject = base64url.toBuffer(attestation.response.attestationObject);
    attestationObject = cbor.decodeCBOR(attestationObject);

    /* authenticatorDataのパース */
    /* TODO:credentialIDってWebAuthnの返り値に入ってるデータと同じなのでその処理 */
    var attestationObjectList = utils.parse(attestationObject.get(2),"attestation");
    if (!attestationObjectList) {
        console.error(username+':attestationObjectのパース失敗...');
        complete = false;
    }

    /* TODO:attestationの検証 */
    var fmt = attestationObject.get(1);
    // if (fmt == 'packed') {
    //     var signature = attestationObject.attStmt.sig;
    //     var signatureData = utils.concatenation(sigAuthenticatorData,sigClientDataJSON);
    //     console.log(signatureData)
    //     var keylist = utils.parsePublicKey(utils.bufToStr(attestationObjectList.credentialPublicKey));
    //     var tpk = keylist.tpk;
    //     var apk = keylist.apk;
    //     var signCheck = await utils.validationSignature(tpk,apk,signature,base64url.encode(signatureData),utils.createPolicy(database[username].attributes));
    //     if (signCheck) {
    //         console.log(username+':署名検証に成功しました.送られたattestationは正しいattestationです.');
    //     } else {
    //         console.log(username+':署名検証に失敗しました.送られたattestationは間違ったattestationです.');
    //         complete = false;
    //     }
    // }

    /* 各種パラメータの検証 */
    // originの検証
    if (attestationExpectations.origin == clientDataJSON.origin) {
        // console.log(username+':originが一致しました.');
    } else {
        console.log(username+':originが一致しません.');
        complete = false;
    }

    // rpIdの検証
    var sha256 = crypto.createHash('sha256');
    sha256.update(attestationExpectations.rpid);
    var rpid = sha256.digest();
    var client_rpid = Buffer.from(attestationObjectList.rpIdHash);
    if (Buffer.compare(rpid,client_rpid) == 0) {
        // console.log(username+':rpIdのHashが一致しました.');
    } else {
        console.log(username+':rpIdのHashが一致しません.');
        complete = false;
    }

    // typeの検証
    if (clientDataJSON.type == 'webauthn.create') {
        // console.log(username+':typeは正しい値になっています.');
    } else {
        console.log(username+':typeが予期される値ではありませんでした.');
        complete = false;
    }

    // flagsの検証
    // 一旦省略

    if (complete) {
        /* TODO:公開鍵の登録処理 */
        var credId = base64url.encode(attestationObjectList.credentialId);
        var apk = base64url.encode(attestationObjectList.credentialPublicKey);
        var counter = Buffer.from(attestationObjectList.counter).readIntBE(0,4,false);
        database[username].attestation.push({
            apk: apk,
            counter: counter,
            fmt: fmt,
            credId: credId
        });
        if (database[username].attribute_table != undefined) {
            if (database[username].attribute_table.indexOf(database[username].attributes) == -1) {
                database[username].attribute_table.push(database[username].attributes)
            }
        }
        // // console.log(database[username]);
        var filepath = './public/DB/'+username+'.json';
        utils.writeKeyFile(filepath,JSON.stringify(database[username]));
        res.send({
            status: 'ok',
            message: username+':登録完了しました.'
        });
    } else {
        res.send({
            status: 'failed',
            message: username+':登録失敗しました.'
        });
    }
    console.timeEnd('/attestation/result');
});

module.exports = router;