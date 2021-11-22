package go_base_api_auth

import (
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/imdario/mergo"
	logging "github.com/lordtor/go-logging"
	version "github.com/lordtor/go-version"
)

type JSONResult struct {
	Code    int         `json:"code" `
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type Claims struct {
	IP           string   `json:"ip"`
	Authorized   bool     `json:"authorized"`
	Service      string   `json:"service"`
	Version      string   `json:"version"`
	Methods      []string `json:"methods"`
	ServiceAgent string   `json:"userId"`
	jwt.StandardClaims
}

type JwtToken struct {
	Token string `json:"token"`
}

type Agent struct {
	Name    string   `json:"name" yaml:"name"`
	Methods []string `json:"methods" yaml:"methods"`
	IP      string   `json:"ip" yaml:"ip"`
}

type Token struct {
	EncryptString string  `json:"-" yaml:"encrypt_string"`
	TokenTimeout  int     `json:"token_timeout" yaml:"token_timeout"`
	App           string  `json:"app" yaml:"app"`
	Host          string  `json:"host" yaml:"host"`
	Version       string  `json:"version" yaml:"version"`
	Agents        []Agent `json:"agents" yaml:"agents"`
}

func (t *Token) Init() {
	err := mergo.Merge(t, Token{
		EncryptString: "7ed90edaac1de08f7227f2cb5aa8ba87b13caf1ea328652c498e9c518b1f9435",
		TokenTimeout:  15,
		App:           "main",
		Host:          "localhost",
		Version:       version.GetVersion().Version,
	})
	if err != nil {
		logging.Log.Error("Cannot Merge data: ", err)
	}
}

type SecurityToken struct {
	Security Oauth2Token `json:"security" yaml:"security"`
}
type Oauth2Token struct {
	Oauth2 ResourceToken `json:"oauth2" yaml:"oauth2"`
}

type ResourceToken struct {
	Resource Jwt `json:"resource" yaml:"resource"`
}

type Jwt struct {
	JWT PublicToken `json:"jwt" yaml:"jwt"`
}

type PublicToken struct {
	KeyValue string `yaml:"public-key" yaml:"key-value"`
}
