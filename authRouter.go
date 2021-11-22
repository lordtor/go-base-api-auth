package go_base_api_auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"encoding/json"

	jwt "github.com/dgrijalva/jwt-go"
	muxContext "github.com/gorilla/context"
	"github.com/gorilla/mux"
	common_lib "github.com/lordtor/go-common-lib"
	logging "github.com/lordtor/go-logging"
)

var (
	DefaultCT = []string{"Content-Type", "application/json"}
	Con       = Token{}
)

func Resp(data *JSONResult, w http.ResponseWriter) {
	w.Header().Set(DefaultCT[0], DefaultCT[1])
	resp, err := json.Marshal(data)
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(data.Code)
	intE, err := w.Write(resp)
	if err != nil {
		http.Error(w, fmt.Sprint(err), intE)
		return
	}
}

func RouterAuth(tokenSettings Token) *mux.Router {
	Con = tokenSettings
	Con.Init()
	logging.Log.Debug(Con)
	router := mux.NewRouter()
	appSubRouter := router.PathPrefix("/api/v1/").Subrouter()

	appSubRouter.HandleFunc("/createToken", CreateTokenEndpoint).Methods("POST")
	appSubRouter.HandleFunc("/readToken", ProtectedEndpoint).Methods("GET")
	appSubRouter.HandleFunc("/validateToken", ValidateMiddleware(ValidateToken)).Methods("GET")
	return router
}

// CreateTokenEndpoint godoc
// @Summary Create agent token
// @Tags auth
// @Description Create JWT token by header Service-Agent & user IP
// @Accept  json
// @Produce  json
// @Success 201 {object}  JSONResult{data=JwtToken} "desc"
// @Failure 400,406 {object} JSONResult
// @Failure 500 {object} JSONResult
// @Router /auth/api/v1/createToken [post]
// @Param Service-Agent header string true "Service-Agent"
// @Param X-FORWARDED-FOR header string false "X-FORWARDED-FOR"
func CreateTokenEndpoint(w http.ResponseWriter, r *http.Request) {
	// GET IP & ServiceAgent
	a, err := ClientInfo(r)
	if err != nil {
		Resp(&JSONResult{
			Code:    http.StatusNotAcceptable,
			Message: err.Error(),
			Data:    nil,
		}, w)
		return
	}
	c := Claims{
		IP:           a.IP,
		ServiceAgent: a.Name,
		Authorized:   true,
		Service:      Con.App,
		Version:      Con.Version,
		Methods:      a.Methods,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * time.Duration(Con.TokenTimeout)).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}
	logging.Log.Debug(c)
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	tokenString, err := at.SignedString([]byte(Con.EncryptString))
	if err != nil {
		Resp(&JSONResult{
			Code:    http.StatusInternalServerError,
			Message: err.Error(),
			Data:    nil,
		}, w)
		return
	}
	w.Header().Set("Authorizations", tokenString)
	logging.Log.Debug(tokenString)
	Resp(&JSONResult{
		Code:    http.StatusCreated,
		Message: "Token created!",
		Data:    JwtToken{Token: tokenString},
	}, w)

}

// ProtectedEndpoint godoc
// @Summary Read token info
// @Tags auth
// @Description Read token info & return
// @Accept  json
// @Produce  json
// @Param token query string false "JWT token"
// @Success 200 {object}  JSONResult{data=Claims} "desc"
// @Failure 400,404 {object} JSONResult
// @Failure 500 {object} JSONResult
// @Router /auth/api/v1/readToken [get]
func ProtectedEndpoint(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	token, _ := jwt.Parse(params["token"][0], func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("There was an error")
		}
		return []byte(Con.EncryptString), nil
	})
	logging.Log.Debug(token.Claims)
	if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		c := &Claims{}
		r, err := json.Marshal(token.Claims)
		json.Unmarshal(r, &c)
		// err := mapstructure.Decode(claims, &c)
		logging.Log.Trace(c)
		if err != nil {
			Resp(&JSONResult{
				Code:    http.StatusInternalServerError,
				Message: err.Error(),
				Data:    nil,
			}, w)
			return
		}
		Resp(&JSONResult{
			Code:    http.StatusOK,
			Message: "",
			Data:    c,
		}, w)
	} else {
		Resp(&JSONResult{
			Code:    http.StatusUnauthorized,
			Message: "Invalid authorization token",
			Data:    nil,
		}, w)
	}
}

func ClientInfo(r *http.Request) (*Agent, error) {
	a := &Agent{}
	if r.Header.Get("X-FORWARDED-FOR") != "" {
		a.IP = strings.Split(r.Header.Get("X-FORWARDED-FOR"), ":")[0]
	} else {
		a.IP = strings.Split(r.RemoteAddr, ":")[0]
	}
	a.Name = r.Header.Get("Service-Agent")
	for i := 0; i < len(Con.Agents); i++ {
		if Con.Agents[i].Name == a.Name {
			a.Methods = Con.Agents[i].Methods
			return a, nil
		}
	}
	return nil, errors.New("Agent not valid")
}

func GetClaims(r *http.Request) (*Claims, error) {
	decoded := muxContext.Get(r, "decoded")
	claims := &Claims{}
	dec, err := json.Marshal(decoded)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(dec, &claims)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

func ValidClient(r *http.Request) (bool, error) {
	claims, err := GetClaims(r)
	if err != nil {
		return false, err
	}
	a, err := ClientInfo(r)
	if err != nil {
		return false, err
	}
	if a.IP == claims.IP &&
		a.Name == claims.ServiceAgent &&
		Con.App == claims.Service &&
		Con.Version == claims.Version {
		return true, nil
	} else {
		msg := map[string]string{
			a.IP:        claims.IP,
			a.Name:      claims.ServiceAgent,
			Con.App:     claims.Service,
			Con.Version: claims.Version,
		}
		logging.Log.Error(msg)
		return false, errors.New("Client data not valid")
	}
}
func ValidMethod(r *http.Request) (bool, error) {
	claims, err := GetClaims(r)
	if err != nil {
		return false, err
	}
	logging.Log.Debug(r.RequestURI)
	method := strings.Split(strings.Replace(r.RequestURI, fmt.Sprintf("/%s", Con.App), "", -1), "?")[0]
	logging.Log.Debug(method)
	a, err := ClientInfo(r)
	if err != nil {
		return false, err
	}
	if common_lib.SliceContain(a.Methods, method) &&
		common_lib.SliceContain(claims.Methods, method) {
		return true, nil
	} else if common_lib.SliceContain(a.Methods, "*") &&
		common_lib.SliceContain(claims.Methods, "*") {
		return true, nil
	}

	return false, errors.New("Method Not Allowed!")
}

func ValidateMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		authorizationHeader := req.Header.Get("Authorization")
		if authorizationHeader != "" {
			bearerToken := strings.Split(authorizationHeader, " ")
			var token *jwt.Token
			var err error
			if len(bearerToken) == 2 {
				token, err = jwt.Parse(bearerToken[1], func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("There was an error")
					}
					return []byte(Con.EncryptString), nil
				})
			} else {
				token, err = jwt.Parse(authorizationHeader, func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("There was an error")
					}
					return []byte(Con.EncryptString), nil
				})
			}
			if err != nil {
				Resp(&JSONResult{
					Code:    http.StatusUnauthorized,
					Message: err.Error(),
					Data:    nil,
				}, w)
				return
			}
			muxContext.Set(req, "decoded", token.Claims)
			validData, errs := ValidClient(req)
			validMethod, errss := ValidMethod(req)
			if token.Valid && validData && validMethod {
				next(w, req)
			} else if errss != nil {
				Resp(&JSONResult{
					Code:    http.StatusMethodNotAllowed,
					Message: fmt.Sprint(errss),
					Data:    nil,
				}, w)
			} else if errs != nil {
				Resp(&JSONResult{
					Code:    http.StatusForbidden,
					Message: fmt.Sprint(errs),
					Data:    nil,
				}, w)
			} else {
				Resp(&JSONResult{
					Code:    http.StatusForbidden,
					Message: "Invalid authorization token",
					Data:    nil,
				}, w)
			}

		} else {
			Resp(&JSONResult{
				Code:    http.StatusForbidden,
				Message: "An authorization header is required",
				Data:    nil,
			}, w)
		}
	})
}

// ValidateToken godoc
// @Summary Validate auth token
// @Tags auth
// @Description Validate auth token & show info if valid
// @Accept  json
// @Produce  json
// @Success 200 {object}  JSONResult{data=Claims} "desc"
// @Failure 400,404,405 {object} JSONResult
// @Failure 500 {object} JSONResult
// @Security ApiKeyAuth
// @Param Service-Agent header string true "Service-Agent"
// @Router /auth/api/v1/validateToken [get]
func ValidateToken(w http.ResponseWriter, r *http.Request) {
	logging.Log.Debug("RUN")
	claims, err := GetClaims(r)
	if err != nil {
		Resp(&JSONResult{
			Code:    http.StatusInternalServerError,
			Message: err.Error(),
			Data:    nil,
		}, w)
	}
	Resp(&JSONResult{
		Code:    http.StatusOK,
		Message: "",
		Data:    claims,
	}, w)
}
