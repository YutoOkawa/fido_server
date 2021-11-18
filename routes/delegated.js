const express = require('express');
const base64url = require('base64url');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const fs = require('fs');
const router = express.Router();
const utils = require('../public/utils.js')
const coreUtils = require('../public/js/coreUtils')
const cbor = require('../public/js/cbor');
router.use(bodyParser.json());

let database = {};

router.post('/options',async function(req,res) {
    console.time('/delegated/options')
    var registerOptions = {
        rp: {},
        user: {},
    };
    
    let username = req.body.username;
    let delegatedUsername = req.body.delegatedUsername;
    let policy = req.body.policy;
    let attributes = req.body.attributes;
    var errorMessage = "";
    var filepath = './public/DB/' + username + '.json';

    if (fs.existsSync(filepath)) {
        database[username] = utils.readKeyFile(filepath);
        database[username] = JSON.parse(database[username]);
        if (database[username].attribute_table==undefined) {
            var attribute_table = []
        } else { /* delegatedUserの属性集合に追加する */
            var attribute_table = database[username].attribute_table;
        }
    } else {
        database[username] = {}
        var attribute_table = []
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

    // allowCredentialsの設定
    var allowCredentials = [];
    allowCredentials.push({
        type: 'ABS',
        id: database[username].attestation[0].credId,
        trasports: ['ble']
    });

    // 各種値の設定
    utils.setOpt(registerOptions.rp,"name",utils.config.FIDO_RP_NAME);
    utils.setOpt(registerOptions.rp,"id",utils.config.FIDO_RPID);
    utils.setOpt(registerOptions.rp,"icon",utils.config.FIDO_RP_ICON);
    utils.setOpt(registerOptions.user,"id",database[username].id);
    utils.setOpt(registerOptions.user,"name",username);
    utils.setOpt(registerOptions.user,"displayName",username);
    utils.setOpt(registerOptions,"attributes",attributes);
    utils.setOpt(registerOptions,"challenge",challenge);
    utils.setOpt(registerOptions,"pubKeyCredParams",pubKeyCredParam);
    utils.setOpt(registerOptions,"userVerification",utils.config.authenticatorUserVerification);
    utils.setOpt(registerOptions,"allowCredentials",allowCredentials);
    utils.setOpt(registerOptions,"timeout",utils.config.timeout);
    utils.setOpt(registerOptions,"attestation",utils.config.attestation);
    utils.setOpt(registerOptions,"errorMessage",errorMessage);
    utils.setOpt(registerOptions,"status","ok");

    database[username] = {
        name: username,
        delegatedUsername: delegatedUsername, /* 委任者情報の記録 */
        registered: true,
        id: database[username].id,
        attributes: attributes,
        policy: policy,
        attestation: database[username].attestation,
        challenge: registerOptions.challenge,
        attribute_table: attribute_table
    };

    console.timeEnd('/delegated/options')
    res.send(registerOptions);
});

router.post('/result',async function(req,res) {
    console.time('/delegated/result');
    var complete = true;
    var attestation = req.body.attestation;
    var username = req.body.username;
    var delegatedUsername = req.body.delegatedUsername;
    
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
            rpid: utils.config.FIDO_RPID,
            policy: database[username].policy,
            apk: database[username].attestation[0].apk,
            delegatedUsername: database[username].delegatedUsername
        };
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
    var attestationObjectList = utils.parse(attestationObject.get(2),"attestation");
    if (!attestationObjectList) {
        console.error(username+':attestationObjectのパース失敗...');
        complete = false;
    }

    var fmt = attestationObject.get(1);

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
    if (clientDataJSON.type == 'webauthn.delegate') {
        // console.log(username+':typeは正しい値になっています.');
    } else {
        console.log(username+':typeが予期される値ではありませんでした.');
        complete = false;
    }

    // flagsの検証

    // delegatedUserNameの検証
    if (attestationExpectations.delegatedUsername != delegatedUsername) {
        console.log(delegatedUsername+':delegatedUsernameが一致しません。');
        complete = false;
    }

    // 署名検証
    var signData = utils.concatenation(attestationObject.get(2).slice(0,37), utils.generateClientDataHash(clientDataJSON));
    signData = utils.concatenation(signData, Buffer.from(attestationExpectations.policy));
    console.log(signData);
    var apk = base64url.toBuffer(attestationExpectations.apk);
    apk = cbor.decodeCBOR(apk);
    apk = coreUtils.BytesToKey(apk);
    var tpk = coreUtils.readKey('./public/DB/localhost.tpk');

    var signCheck = utils.validationSignature(tpk, apk, attestation.signature, signData, attestationExpectations.policy);
    if (!signCheck) {
        console.log('署名検証に失敗しました。');
        complete = false;
    }

    if (complete) { /* 完了処理 */
        if (database[username].attribute_table != undefined) {
            if (database[username].attribute_table.indexOf(database[username].attributes) == -1) {
                database[username].attribute_table.push(database[username].attributes)
            }
        } else {
            
        }
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
    console.timeEnd('/delegated/result');
});

module.exports = router;