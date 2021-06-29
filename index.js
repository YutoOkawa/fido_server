var express = require('express');
var app = express();

var fs = require('fs');
var https = require('https');
var option = {
    key: fs.readFileSync('./cert/server_key.pem'),
    cert: fs.readFileSync('./cert/server_crt.pem')
};

var cors = require('cors');

app.use(cors());

var server = https.createServer(option, app);

var attestation = require('./routes/attestation');
var assertion = require('./routes/assertion');

app.use('/attestation', attestation);
app.use('/assertion', assertion);

app.get('*', function(req,res) {
    res.send('This is a new FIDO2 Server by core libray.');
});

app.post('/test', function(req, res) {
    res.send({
        message: req.body.text
    });
});

server.listen(3000);