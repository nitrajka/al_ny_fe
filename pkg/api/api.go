package api

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"net/http"
	"strconv"
	"strings"
)

type UserServer struct {
	apiAddr string
	*gin.Engine
	tokens      map[uint64]string
	oauthConfig *oauth2.Config
	template    Template
	selfAddr string
}

func NewUserServer(beAddr, clientId, clientSecret string, selfAddr string) (*UserServer, error) {
	us := new(UserServer)
	us.apiAddr = beAddr

	router := gin.Default()
	router.GET("/", us.GetLogin)
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
	router.GET("/password/forgot", us.ForgotPassword)
	router.POST("/password/forgot", us.SendMail)
	router.GET("/password/forgot/:token/:mail", us.NewPassword)
	router.POST("/password/new/:token/:mail", us.RefreshPassword)

	us.oauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8002/login/google/success",
		ClientID:     clientId,
		ClientSecret: clientSecret,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}

	us.selfAddr = selfAddr
	us.Engine = router
	us.tokens = make(map[uint64]string)
	return us, nil
}

func (u *UserServer) LoginGoogle(c *gin.Context) {
	oauthState := generateStateOauthCookie(c.Writer)
	t := u.oauthConfig.AuthCodeURL(oauthState)
	c.Redirect(http.StatusTemporaryRedirect, t)
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
			return
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

	loadAndExecuteTemplate(c, []string{"./templates/displayProfile.html"}, Template{User: &signUpResponse.User})
}

func (u *UserServer) GetLogin(c *gin.Context) {
	loadAndExecuteTemplate(c, []string{"./templates/login.html", "./templates/loginSignupForm.html"},
		Template{Type: &struct{ IsLogin bool }{IsLogin: true }, Msg: u.template.Msg} )
	u.template.Reset()
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

		u.tokens[signUpResponse.User.ID] = signUpResponse.Token

		loadAndExecuteTemplate(c, []string{"./templates/displayProfile.html"}, Template{User: &signUpResponse.User})
		return
	}

	var msg string

	err = json.Unmarshal(responseBodyContent, &msg)
	if err != nil {
		msg = "could not login successfully, please try again later"
	}

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

	responseBodyContent := getResponseContent(resp)

	if resp.StatusCode == http.StatusOK {
		var user *User
		err = json.Unmarshal(responseBodyContent, &user)
		if err != nil {
			//go one step back
			u.template.Set(u.template.Msg + "\n" + "update was successful", nil, nil)
			u.DisplayUser(c)
			return
		}

		path := "/user/" + strconv.Itoa(int(user.ID))
		c.Redirect(http.StatusFound, path)
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

func (u *UserServer) ForgotPassword(c *gin.Context) {
	loadAndExecuteTemplate(c, []string{"./templates/forgotPassword.html"}, Template{})
}

func (u *UserServer) SendMail(c *gin.Context) {
	err := c.Request.ParseForm()
	if err != nil {
		loadAndExecuteTemplate(c, []string{"./templates/forgotPassword.html"},
			Template{Msg: "sorry, could not parse form, please, try again later"})
		return
	}

	email := c.Request.Form.Get("username")

	//todo:
	payload := fmt.Sprintf(`{"email": "%s", "redirectUrl": "%s"}`, email, "http://"+u.selfAddr+"/password/forgot/:token")
	res, err := http.Post(u.apiAddr + "/password/reset", "application/json", strings.NewReader(payload))
	if err != nil {
		loadAndExecuteTemplate(c, []string{"./templates/forgotPassword.html"},
			Template{Msg: "sorry, could not connect to server, please, try again later"})
		return
	}

	if res.StatusCode == http.StatusOK {
		loadAndExecuteTemplate(c, []string{"./templates/forgotPassword.html"},
			Template{Msg: "email sent successfully, please follow the link in your post"})
		return
	}

	content := getResponseContent(res)

	var msg string
	err = json.Unmarshal(content, &msg)
	if err != nil {
		msg = "sorry, could not send reset password email, please try again later"
	}

	loadAndExecuteTemplate(c, []string{"./templates/forgotPassword.html"},
		Template{Msg: msg})
}

func (u *UserServer) NewPassword(c *gin.Context) {
	token := c.Param("token")
	mail := c.Param("mail")

	payload := fmt.Sprintf(`{"token": "%s", "email": "%s"}`, token, mail)
	resp, err := http.Post(u.apiAddr+"/password/reset/validate", "application/json", strings.NewReader(payload))

	content := getResponseContent(resp)

	if resp.StatusCode == http.StatusOK {
		//display template to show form for new email
		loadAndExecuteTemplate(c, []string{"./templates/resetPassword.html"}, Template{Token: token, Mail: mail, ValidToken: true})
		return
	}

	var msg string
	err = json.Unmarshal(content, &msg)
	if err != nil {
		msg = "sorry, could not send reset password email, please try again later"
	}

	loadAndExecuteTemplate(c, []string{"./templates/resetPassword.html"},
		Template{Msg: msg, ValidToken: false})
}

func (u *UserServer) RefreshPassword(c *gin.Context) {
	token := c.Param("token")
	mail := c.Param("mail")

	err := c.Request.ParseForm()
	if err != nil {
		loadAndExecuteTemplate(c, []string{"./templates/resetPassword"},
		Template{ValidToken: true, Mail: mail, Token: token, Msg: "could not parse form"})
		return
	}

	newPassword := c.Request.FormValue("password")
	payload := fmt.Sprintf(`{"username": "%s", "password": "%s", "token": "%s"}`, mail, newPassword, token )
	resp, err := http.Post("/password/renew", "application/json", strings.NewReader(payload))

	content := getResponseContent(resp)

	if resp.StatusCode != http.StatusOK {
		var msg string

		err = json.Unmarshal(content, &msg)
		if err != nil {
			msg = "sorry, could not send reset password email, please try again later"
		}

		loadAndExecuteTemplate(c, []string{"./templates/resetPassword.html"},
			Template{Msg: msg, ValidToken: false})
		return
	}

	loadAndExecuteTemplate(c, []string{"./templates/login"}, Template{Msg: "password successfully renewed"})
}