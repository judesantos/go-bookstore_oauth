package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/judesantos/go-bookstore_utils/rest_errors"
	"github.com/mercadolibre/golang-restclient/rest"
)

const (
	headerXPublic   = "X-Public"
	headerXClientId = "X-Client-Id"
	headerXUserId   = "X-User-Id"

	paramsAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8181",
		Timeout: 200 * time.Millisecond,
	}
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id"`
}

//
// IsPublic
//
func IsPublic(req *http.Request) bool {
	if req == nil {
		return true
	}
	return req.Header.Get(headerXPublic) == "true"
}

//
// GetUserId - Get user id
//
func GetUserId(req *http.Request) int64 {
	if req == nil {
		return 0
	}

	callerId, err := strconv.ParseInt(req.Header.Get(headerXUserId), 10, 64)
	if err != nil {
		return 0
	}

	return callerId
}

//
// GetClientId - Get client id
//
func GetClientId(req *http.Request) int64 {
	if req == nil {
		return 0
	}

	clientId, err := strconv.ParseInt(req.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}

	return clientId
}

//
// AuthenticateRequest - login user
//
func AuthenticateRequest(req *http.Request) rest_errors.IRestError {
	if req == nil {
		return nil
	}

	cleanRequest(req)

	accessTokenId := req.URL.Query().Get(paramsAccessToken)
	if accessTokenId == "" {
		return nil
	}

	at, err := getAccessToken(accessTokenId)
	if err != nil {
		//if err.Status == http.StatusNotFound {
		//	return nil
		//}
		return err
	}

	req.Header.Add(headerXClientId, fmt.Sprintf("%v", at.ClientId))
	req.Header.Add(headerXUserId, fmt.Sprintf("%v", at.UserId))

	return nil
}

func cleanRequest(req *http.Request) {
	if req == nil {
		return
	}
	req.Header.Del(headerXClientId)
	req.Header.Del(headerXUserId)
}

// getAccessToken - get access token from remote oauth service
func getAccessToken(accessTokenId string) (*accessToken, rest_errors.IRestError) {

	res := oauthRestClient.Get(
		fmt.Sprintf("/oauth/access_token?access_token_id=%s", accessTokenId))
	if res == nil || res.Response == nil {
		return nil, rest_errors.InternalServerError(
			"Access token error, invalid rest response",
			errors.New("oauth client failed to get access token"))
	}

	if res.StatusCode > 299 {
		var rerr rest_errors.IRestError
		err := json.Unmarshal(res.Bytes(), &rerr)
		if err != nil {
			return nil, rest_errors.InternalServerError(
				"Access token error, interface error", err)
		}
		return nil, rerr
	}

	var at accessToken

	if err := json.Unmarshal(res.Bytes(), &at); err != nil {
		return nil, rest_errors.InternalServerError(
			"Access token error, can not process response", err)
	}

	return &at, nil
}
