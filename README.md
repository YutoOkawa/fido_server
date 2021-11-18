# Project Setup
```bash
npm install
npm install --save /path_to_core/javascript
```

# Usage
```bash
node index.js
```

# Caution
## CertErrorについて
Rpアプリケーションからhttps通信を要求しますが、オレオレ証明書のためCertErrorが出ます。

証明書が信頼できないとアクセスができませんが、一度GoogleChromeで
```bash
https://localhost:3000
```
にアクセスしていただいて、画面上で
```bash
this is unsafe
```
と打つとアクセスできるようになります。

ローカル上で動かすための暫定処理になります。

(FIDOはhttps通信が必須とされているためその部分に準拠しています。)

## coreライブラリについて
暗号ライブラリcoreはnpmで直接インストールすることができず、ライブラリをダウンロードして自分でnpm installする必要があります。

適当な場所にcoreをダウンロードしていただいて、
```bash
npm install --save /path_to_core/javascript
```
とすることでcoreを利用することができます。