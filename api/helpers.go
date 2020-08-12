package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"html/template"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"time"
)

const oauthGoogleUrlAPI = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="

func getUser(restApiAddr, token string) *User {
	req, _ := http.NewRequest(http.MethodGet, restApiAddr + "/user", nil )
	resp, _ := http.DefaultClient.Do(req)

	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = ioutil.ReadAll(resp.Body)
	}
	// Restore the io.ReadCloser to its original state
	resp.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	var user *User
	_ = json.Unmarshal(bodyBytes, &user)

	return user
}

func parseFormToPayload(values url.Values) string {
	buff := new(bytes.Buffer)
	buff.Write([]byte("{"))
	for k, v := range values {
		buff.Write([]byte("\""))
		buff.Write([]byte(k))
		buff.Write([]byte("\""))
		buff.Write([]byte(":"))
		buff.Write([]byte("\""))
		buff.Write([]byte(v[0]))
		buff.Write([]byte("\""))
		buff.Write([]byte(","))
		//fmt.Printf("%v = %v\n", k, v)
	}
	payload := buff.String()
	buff.Reset()
	buff.Write([]byte(payload[:len(payload)-1]))
	buff.Write([]byte("}"))

	return buff.String()
}

func loadAndExecuteTemplate(c *gin.Context, names []string, tmpl Template) {
	template, err1 := template.ParseFiles(names...)
	if err1 != nil {
		c.JSON(http.StatusInternalServerError, "could not parse template: " + err1.Error())
		return
	}

	_ = template.Execute(c.Writer, tmpl)
}

func generateStateOauthCookie(w http.ResponseWriter) string {
	var expiration = time.Now().Add(365 * 24 * time.Hour)

	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: "oauthstate", Value: state, Expires: expiration}
	http.SetCookie(w, &cookie)

	return state
}

func (u * UserServer) getUserDataFromGoogle(code string) ([]byte, *oauth2.Token, error) {
	// Use code to get token and get user info from Google.

	token, err := u.oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return nil, nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}
	response, err := http.Get(oauthGoogleUrlAPI + token.AccessToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed read response: %s", err.Error())
	}
	return contents, token, nil
}

func getResponseContent(resp *http.Response) []byte {
	var bodyBytes []byte
	if resp.Body != nil {
		bodyBytes, _ = ioutil.ReadAll(resp.Body)
	}

	// Restore the io.ReadCloser to its original state
	resp.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	return bodyBytes
}