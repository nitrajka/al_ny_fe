package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"html/template"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type UserServer struct {
	apiAddr string
	*gin.Engine
	tokens map[uint64]string
	oauthConfig *oauth2.Config
	template Template
}

func NewUserServer(beAddr, clientId, clientSecret string) (*UserServer, error) {
	us := new(UserServer)
	us.apiAddr = beAddr

	router := gin.Default()
	router.GET("/login/google", us.LoginGoogle)
	router.GET("/login/google/success", us.OauthGoogleCallback)
	router.GET("/login", us.GetLogin)
	router.POST("/login", us.PostLogin)
	router.GET("/logout/:id", us.Logout)
	router.GET("/signup", us.GetSignup)
	router.POST("/signup", us.PostSignup)

	router.GET("/user/:id", us.DisplayUser)
	router.GET("/user/:id/edit", us.DisplayUserToEdit)
	router.POST("/user/:id/edit", us.EditUser)
	//router.GET("/user/forgot", ForgotPassword)
	//router.POST("/user/forgot", SendEmail)
	//router.GET("/user/forgot/:token", NewPassword)
	//router.POST("/user/forgot/:token", RefreshPassword)

	us.oauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8002/login/google/success",
		ClientID:     clientId,
		ClientSecret: clientSecret,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}

	us.Engine = router
	us.tokens = make(map[uint64]string)
	return us, nil
}

func loadAndExecuteTemplate(c *gin.Context, names []string, tmpl Template) {
	template, err1 := template.ParseFiles(names...)
	if err1 != nil {
		c.JSON(http.StatusInternalServerError, "could not parse template: " + err1.Error())
		return
	}

	_ = template.Execute(c.Writer, tmpl)
}

func (u *UserServer) LoginGoogle(c *gin.Context) {
	oauthState := generateStateOauthCookie(c.Writer)
	t := u.oauthConfig.AuthCodeURL(oauthState)
	c.Redirect(http.StatusTemporaryRedirect, t)
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

func (u *UserServer) OauthGoogleCallback(c *gin.Context) {
	oauthState, _ := c.Request.Cookie("oauthstate")

	if c.Request.FormValue("state") != oauthState.Value {
		c.JSON(http.StatusUnauthorized, "gogole login did not went well, please log in again")
		//log.Println("invalid oauth google state")
		//http.Redirect(c.Writer, c.Request, "/", http.StatusTemporaryRedirect)
		return
	}

	_, token, err := u.getUserDataFromGoogle(c.Request.FormValue("code"))
	if err != nil {
		//log.Println(err.Error())
		c.JSON(http.StatusInternalServerError, "")
		http.Redirect(c.Writer, c.Request, "/", http.StatusTemporaryRedirect)
		return
	}

	r, err := http.NewRequest(http.MethodPost, u.apiAddr + "/login/google", nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, "")
		http.Redirect(c.Writer, c.Request, "/", http.StatusTemporaryRedirect)
		return
	}
	r.Header.Add("Authorization", token.AccessToken)
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		c.JSON(http.StatusInternalServerError, "internal server error")
		return
	}

	if resp.StatusCode != http.StatusOK {
		bodyContent := getResponseContent(resp)
		var msg string
		err := json.Unmarshal(bodyContent, &msg)
		if err != nil {
			c.JSON(http.StatusUnauthorized, "could not decode server response")
		}

		c.JSON(http.StatusUnauthorized, msg)
		return
	}

	var signUpResponse *SignUpResponse
	err = json.NewDecoder(resp.Body).Decode(&signUpResponse)
	if err != nil {
		c.JSON(http.StatusInternalServerError, "could not decode response")
		return
	}

	u.tokens[signUpResponse.User.ID] = signUpResponse.Token
	fmt.Println(signUpResponse.Token)

	loadAndExecuteTemplate(c, []string{"./templates/displayProfile.html"}, Template{User: &signUpResponse.User})
}

const oauthGoogleUrlAPI = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="

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

func (u *UserServer) GetLogin(c *gin.Context) {
	loadAndExecuteTemplate(c, []string{"./templates/login.html", "./templates/loginSignupForm.html"},
		Template{Type: &struct{ IsLogin bool }{IsLogin: true }, Msg: u.template.Msg} )
	u.template.Reset()
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

func (u *UserServer) PostLogin(c *gin.Context) {
	err := c.Request.ParseForm()
	if err != nil {
		return
	}

	bodyContent := parseFormToPayload(c.Request.Form)

	resp, err := http.Post(u.apiAddr + "/login", "application/json", strings.NewReader(bodyContent))
	if err != nil {
		loadAndExecuteTemplate(c, []string{"./templates/login.html", "./templates/loginSignupForm.html"},
			Template{Msg: err.Error()})
		return
	}

	responseBodyContent := getResponseContent(resp)

	if resp.StatusCode == http.StatusOK {
		var signUpResponse *SignUpResponse

		err = json.Unmarshal(responseBodyContent, &signUpResponse)
		if err != nil {
			c.JSON(http.StatusInternalServerError, "could not parse response: " + err.Error())
		}

		fmt.Println(signUpResponse.Token)

		u.tokens[signUpResponse.User.ID] = signUpResponse.Token

		loadAndExecuteTemplate(c, []string{"./templates/displayProfile.html"}, Template{User: &signUpResponse.User})
		return
	}

	var msg string

	err = json.Unmarshal(responseBodyContent, &msg)
	if err != nil {
		msg = "could not login successfully, please try again later"
	}

	//loadAndExecuteTemplate(c, []string{"./templates/login.html"}, Template{Msg: msg, Type: struct{ IsLogin bool }{IsLogin: true }})

	u.template.Set(msg, nil, nil)
	u.GetLogin(c)
}

func (u *UserServer) Logout(c *gin.Context) {
	idS := c.Param("id")
	id, err := strconv.Atoi(idS)
	if err != nil {
		u.template.Set("user Id of bad format", nil, nil)
		u.DisplayUser(c)
		return
	}

	req, err := http.NewRequest(http.MethodPost, u.apiAddr + "/logout", strings.NewReader(idS))
	if err != nil {
		u.template.AddMessage( "sorry, could not logout, try again later")
		u.GetSignup(c)
		return
	}

	req.Header.Add("Authorization", u.tokens[uint64(id)])

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		u.template.Set(u.template.Msg + "\n" + "sorry, could not logout, try again later", nil, nil)
		u.GetSignup(c)
		return
	}

	fmt.Println(resp.StatusCode)

	if resp.StatusCode == http.StatusOK {
		id, _ := strconv.Atoi(idS)
		delete(u.tokens, uint64(id))

		u.template.Reset()
		u.GetLogin(c)
		return
	}

	responseBody := getResponseContent(resp)

	var msg string
	err = json.Unmarshal(responseBody, &msg)
	if err != nil {
		msg = "logout unsuccessful, please, try again later"
	}

	fmt.Println(msg)

	u.template.Set(msg, nil, nil)
	u.DisplayUser(c)
}

func (u *UserServer) GetSignup(c *gin.Context) {
	loadAndExecuteTemplate(c, []string{"./templates/signup.html",  "./templates/loginSignupForm.html"},
		Template{Type: &struct{ IsLogin bool }{IsLogin: false }, Msg: u.template.Msg})

	u.template.Reset()
}

func (u *UserServer) PostSignup(c *gin.Context) {
	err := c.Request.ParseForm()
	if err != nil {
		u.template.Set("could not sign up, please try later1", nil, nil)
		u.GetSignup(c)
		return
	}

	body := parseFormToPayload(c.Request.Form)
	resp, err := http.Post(u.apiAddr + "/signup", "application/json", strings.NewReader(body))
	if err != nil {
		u.template.Set("sorry, could not signup, try again later2", nil, nil)
		u.GetSignup(c)
		return
	}

	if resp.StatusCode == http.StatusCreated {
		content := getResponseContent(resp)

		var sr *SignUpResponse

		err := json.Unmarshal(content, &sr)
		if err != nil {
			u.template.Set("sorry, could not signup, try again later3", nil, nil)
			u.GetSignup(c)
			return
		}

		u.tokens[sr.User.ID] = sr.Token

		loadAndExecuteTemplate(c, []string{"./templates/displayProfile.html"}, Template{User: &sr.User})
		return
	}

	content := getResponseContent(resp)

	var msg string
	err = json.Unmarshal(content, &msg)
	if err != nil {
		msg ="sorry, could not signup, try again later4"
	}

	u.template.Set(msg, nil, nil)
	u.GetSignup(c)
	return

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

func (u *UserServer) DisplayUser(c *gin.Context) {
	idString  := c.Param("id")
	id, err := strconv.Atoi(idString)
	token := u.tokens[uint64(id)]

	//getUser by Id
	r, err := http.NewRequest(http.MethodGet, u.apiAddr + "/user/" + idString, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, "could not make request for user info: " + err.Error())
		return
	}
	r.Header.Add("Authorization", token)

	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		c.JSON(http.StatusInternalServerError, "could not make request for user info: " + err.Error())
		return
	}

	responseBodyContent := getResponseContent(resp)

	if resp.StatusCode == http.StatusOK {
		var user *User
		err = json.Unmarshal(responseBodyContent, &user)
		if err != nil {
			//go to login
			u.template.Set("could not proceede, please try again later", nil, nil)
			u.GetLogin(c)
			return
		}

		fmt.Println(user)
		loadAndExecuteTemplate(c, []string{"./templates/displayProfile.html"}, Template{User: user})
		return
	}

	//unauthorized or user does not exist
	var msg string
	err = json.Unmarshal(responseBodyContent, &msg)

	if err != nil {
		msg = "could not load server response, please try again later"
	}

	u.template.Set(msg, nil, nil)
	u.GetLogin(c)
}

func (u *UserServer) DisplayUserToEdit(c *gin.Context) {
	idString  := c.Param("id")
	id, err := strconv.Atoi(idString)
	if err != nil {
		u.template.Set("incorrect ID format", nil, nil)
		u.GetLogin(c)
		return
	}
	token := u.tokens[uint64(id)]

	r, err := http.NewRequest(http.MethodGet, u.apiAddr + "/user/" + idString, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, "could not make request for user info: " + err.Error())
		return
	}
	r.Header.Add("Authorization", token)

	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		c.JSON(http.StatusInternalServerError, "could not make request for user info: " + err.Error())
		return
	}

	responseBodyContent := getResponseContent(resp)

	if resp.StatusCode == http.StatusOK {
		var user *User
		err = json.Unmarshal(responseBodyContent, &user)
		if err != nil {
			u.template.Set("could not load form, please try again later", nil, nil)
			u.DisplayUser(c)
			return
		}

		loadAndExecuteTemplate(c, []string{"./templates/editProfile.html"}, Template{User: user, Msg: u.template.Msg})
		u.template.Reset()
		return
	}


	var msg string
	err = json.Unmarshal(responseBodyContent, &msg)
	if err != nil {
		msg = "could not load form, please try again later"
	}

	u.template.Set(u.template.Msg + "\n" +msg, nil, nil)
	u.DisplayUser(c)
}

func (u *UserServer) EditUser(c *gin.Context) {
	idString  := c.Param("id")
	id, err := strconv.Atoi(idString)
	if err != nil {
		u.template.Set("incorrect ID format", nil, nil)
		u.GetLogin(c)
		return
	}
	token := u.tokens[uint64(id)]


	err = c.Request.ParseForm()
	if err != nil {
		u.template.Set("sorry, could not parse form, try again later", nil, nil)
		u.DisplayUser(c)
		return
	}

	bodyPayload := parseFormToPayload(c.Request.Form)
	fmt.Println(bodyPayload)

	req, err := http.NewRequest(http.MethodPut, u.apiAddr + "/user/" + idString, strings.NewReader(bodyPayload))
	if err != nil {
		u.template.Set(u.template.Msg + "\n" + "could not connect to server, try again later", nil, nil)
		u.DisplayUser(c)
		return
	}
	req.Header.Add("Authorization", token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		u.template.Set(u.template.Msg + "\n" + "could not connect to server, try again later", nil, nil)
		u.DisplayUser(c)
		return
	}

	fmt.Println("server connected")

	responseBodyContent := getResponseContent(resp)

	fmt.Println(resp.StatusCode)
	if resp.StatusCode == http.StatusOK {
		var user *User
		err = json.Unmarshal(responseBodyContent, &user)
		if err != nil {
			//go one step back
			u.template.Set(u.template.Msg + "\n" + "update was successfulr", nil, nil)
			u.DisplayUser(c)
			return
		}

		fmt.Println(user)
		path := "/user/" + strconv.Itoa(int(user.ID))
		fmt.Println(path)
		c.Redirect(http.StatusFound, path)
		//loadAndExecuteTemplate(c, []string{"./templates/displayProfile.html"}, Template{User: user})
		return
	}

	var msg string
	err = json.Unmarshal(responseBodyContent, &msg)
	if err != nil {
		msg = "could not load server response, please, try again later"
	}

	u.template.Set(msg, nil, nil)
	u.DisplayUserToEdit(c)
}

func (u *UserServer) getUser(token string) *User {
	req, _ := http.NewRequest(http.MethodGet, u.apiAddr + "/user", nil )
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