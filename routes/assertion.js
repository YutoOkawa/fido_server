const express = require('express');
const router = express.Router();
const base64url = require('base64url');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const utils = require('../public/utils.js');
const fs = require('fs');
const cbor = require('../public/js/cbor');
const coreUtils = require('../public/js/coreUtils');
router.use(bodyParser.json());

let database = {};

router.post('/options',async function(req,res) {
    console.time('/assertion/options');
    let username = req.body.username;
    let policy = req.body.policy;
    var authnOptions = {
        allowCredentials:{},
        rp:{}
    };
    var errorMessage = "";
    var filepath = './public/DB/' + username + '.json';
    try {
        var data = fs.readFileSync(filepath,'utf-8');
    } catch(e) {
        console.log(e);
        return res.send({
            status: 'failed',
            errorMessage:'ユーザが存在していません'
        });
    }
    database[username] = JSON.parse(data);
    if(!delete database[username].challenge) {
        errorMessage = "DBでエラーが発生しました.";
    }
    // console.log(database[username]);
    database[username].policy = policy;

    // challengeの生成
    var challenge = crypto.randomBytes(utils.config.challengesize);
    challenge = utils.toArrayBuffer(challenge,"challenge");
    challenge = base64url.encode(challenge);
    // console.log(challenge);
    utils.setOpt(database[username],"challenge",challenge);
    // console.log(database[username]);

    // allowCredentialsの設定
    var allowCredentials = [];
    allowCredentials.push({
        type: 'ABS',
        id: database[username].attestation[0].credId,
        transports: ['usb','nfc','ble','internal']
    });

    // 各種値の設定
    utils.setOpt(authnOptions.rp,"id",utils.config.FIDO_RPID);
    utils.setOpt(authnOptions,"challenge",challenge);
    utils.setOpt(authnOptions,"timeout",utils.config.timeout);
    utils.setOpt(authnOptions,"userVerification",utils.config.authenticatorUserVerification);
    utils.setOpt(authnOptions,"allowCredentials",allowCredentials);
    utils.setOpt(authnOptions,"errorMessage",errorMessage);
    utils.setOpt(authnOptions,"status","ok");
    // console.log(authnOptions);
    res.send(authnOptions);
    console.timeEnd('/assertion/options')
});

router.post('/result',async function(req,res) {
    console.time('/assertion/result');
    var complete = true;
    var assertion = req.body.assertion;
    var username = req.body.userid;

    if(database[username] != undefined) {
        var assertionExpectations = {
            challenge: database[username].challenge,
            origin: utils.config.FIDO_ORIGIN,
            rpid: utils.config.FIDO_RPID,
            policy: database[username].policy,
            apk: database[username].attestation[0].apk
        };
        console.log('認証を開始します.');
    } else {
        console.log('error');
        complete = false;
    }

    /* clientDataJSONのパース */
    var clientDataJSON = utils.parseJSON(assertion.response.clientDataJSON);

    /* clientDataHashの事前作成 */
    var clientDataHash = utils.generateClientDataHash(clientDataJSON);

    /* challengeの検証 */
    if (assertionExpectations.challenge == clientDataJSON.challenge) {
        console.log('challengeの検証成功!');
    } else {
        console.log('challengeの検証失敗...');
        complete = false;
    }

    // // authenticatorDataのパース
    // var authenticatorData = base64url.toBuffer(assertion.response.authenticatorData);
    // authenticatorData = utils.toArrayBuffer(authenticatorData,"authenticatorData");
    // authenticatorData = utils.parse(authenticatorData,"assertion");
    // if(!authenticatorData) {
    //     console.error('attestationObjectのパース失敗...');
    //     complete = false;
    // }

    /* authenticatorDataのデコード */
    var authenticatorData = base64url.toBuffer(assertion.response.authenticatorData);
    authenticatorData = cbor.decodeCBOR(authenticatorData);

    /* authenticatorDataのパース */
    var assertionList = utils.parse(authenticatorData.get(2), "authenticatorData");
    if (!assertionList) {
        console.error(username+':assertionのパース失敗...');
        complete = false;
    }

    /* 各種パラメータの検証 */
    // originの検証
    if (assertionExpectations.origin == clientDataJSON.origin) {
        console.log('originが一致しました.');
    } else {
        console.log('originが一致しません.');
        complete = false;
    }

    // rpIdの検証
    var sha256 = crypto.createHash('sha256');
    sha256.update(assertionExpectations.rpid);
    var rpid = sha256.digest(assertionList.rpid);
    var client_rpid = Buffer.from(assertionList.rpIdHash);
    if (Buffer.compare(rpid,client_rpid) == 0) {
        console.log(username+':rpIdのHashが一致しました.');
    } else {
        console.log(username+':rpIdのHashが一致しません.');
        complete = false;
    }


    // typeの検証
    if (clientDataJSON.type == 'webauthn.get') {
        console.log('typeは正しい値になっています.');
    } else {
        console.log('typeが予期される値ではありませんでした.');
        complete = false;
    }

    // flagsの検証
    // 一旦省略

    // TODO:署名検証機能
    /* 署名検証 */
    var signData = utils.concatenation(authenticatorData.get(2), clientDataHash);
    signData = utils.concatenation(signData, Buffer.from("A"));
    // 公開鍵の取得(DB->apk, file->tpk)
    var apk = base64url.toBuffer(assertionExpectations.apk);
    apk = cbor.decodeCBOR(apk);
    apk = coreUtils.BytesToKey(apk);
    var tpk = coreUtils.readKey('./public/DB/localhost.tpk');

    var signCheck = utils.validationSignature(tpk, apk, assertion.response.signature, signData, "A");
    if (signCheck) {
        console.log('署名検証に成功しました.');
    } else {
        console.log('署名検証に失敗しました');
        complete = false;
    }

    if(complete) {
        var filepath = './public/DB/' + username + '.json';
        utils.writeKeyFile(filepath,JSON.stringify(database[username]));
        res.send({
            status: 'ok',
            message: '認証完了しました.'
        });
    } else {
        res.send({
            status: 'failed',
            message: '認証失敗しました.'
        });
    }
    console.timeEnd('/assertion/result');
});

module.exports = router;