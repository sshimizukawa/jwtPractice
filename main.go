package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// JWTの署名検証を行うため情報
type Header struct {
	Alg string `json:"alg"` // algorithm: 暗号化アルゴリズム
	Typ string `json:"typ"` // mediaType: JWTを指定(大文字推奨)
}

// 内容は任意でアプリケーション固有のものを定義します。
type Payload struct {
	Sub string `json:"sub"` // subject: 認証の対象となるユーザの識別子.文字列かリソースURI。
	Iat int    `json:"iat"` // issuedAt: JWTの発行日時
	/* その他の予約語
	Iss string `json:"iss"` // issuer: JWTの発行者
	Aud string `json:"aud"` // audience: JWTの受信者
	Exp int    `json:"exp"` // expire: 有効期限
	Nbf string `json:"nbf"` // notBefore: JWT変更前の時間
	Jti string `json:"jti"` // jwtID: JWTのID
	*/
	// その他自由に定義できます
}

// jwtの仕様はRFC7519で定められている
// 署名付きデータはJWS(RFC7525)
// 暗号化する場合はJWE(RFC7516)
// JWSを使った署名付きJWTが一般的
// 参考: https://datatracker.ietf.org/doc/html/rfc7519
func main() {
	// ヘッダー作成
	header := Header{
		Alg: "HS256",
		Typ: "JWT",
	}
	hBytes, _ := json.Marshal(header)
	headerJson := string(hBytes)
	print("ヘッダーJSON", headerJson)

	// ペイロード作成
	iatTime, _ := time.Parse("2006-01-02", "2023-01-01")
	payload := Payload{
		Iat: int(iatTime.Unix()),
		Sub: "user_id",
	}
	pBytes, _ := json.Marshal(payload)
	payloadJson := string(pBytes)
	print("ペイロードJSON", payloadJson)

	// 署名作成
	headerBase64 := base64.StdEncoding.EncodeToString([]byte(headerJson))
	payloadBase64 := base64.StdEncoding.EncodeToString([]byte(payloadJson))
	signature := fmt.Sprintf("%s.%s", headerBase64, payloadBase64)
	print("署名", signature)

	// jwtToken作成
	jwtToken := fmt.Sprintf("%s.%s.%s", headerBase64, payloadBase64, signature)
	print("JWTトークン", jwtToken)
}

func print(name string, value string) {
	fmt.Printf("%s\n%s\n\n", name, value)
}
