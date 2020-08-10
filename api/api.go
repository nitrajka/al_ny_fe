package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"html/template"
	"io/ioutil"
	"net/http"
	"strconv"
)

type UserServer struct {
	apiAddr string
	*gin.Engine
	tokens map[uint64]string
}

func NewUserServer(beAddr string) (*UserServer, error) {
	us := new(UserServer)
	us.apiAddr = beAddr

	router := gin.Default()
	router.GET("/login", us.GetLogin)
	router.POST("/login", us.PostLogin)
	//router.POST("/login/google", GoogleLogin)
	router.GET("/signup", us.GetSignup)
	//router.GET("/signup", PostSignup)

	router.GET("/user/:id", us.DisplayUser)
	router.GET("/user/:id/edit", us.DisplayUserToEdit)
	router.POST("/user/:id/edit", us.EditUser)
	//router.PUT("/user/:id", UpdateUser)
	//router.GET("/user/forgot", ForgotPassword)
	//router.POST("/user/forgot", SendEmail)
	//router.GET("/user/forgot/:token", NewPassword)
	//router.POST("/user/forgot/:token", RefreshPassword)

	us.Engine = router
	us.tokens = make(map[uint64]string)
	return us, nil
}


func (u *UserServer) GetLogin(c *gin.Context) {
	tmpl, err := template.ParseFiles("./templates/login.html", "./templates/loginSignupForm.html")
	if err != nil {
		c.JSON(http.StatusInternalServerError, "could not parse template: " + err.Error())
		return
	}
	err = tmpl.Execute(c.Writer, Form{Msg: "" , Type: struct{ IsLogin bool }{IsLogin: true }})

	if err != nil {
		c.JSON(http.StatusInternalServerError, "could not execute template: " + err.Error())
		return
	}
}

func (u *UserServer) PostLogin(c *gin.Context) {
	err := c.Request.ParseForm()
	if err != nil {
		return
	}

	buff := new(bytes.Buffer)
	buff.Write([]byte("{"))
	for k, v := range c.Request.Form {
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

	resp, err := http.Post(u.apiAddr + "/login", "application/json", buff)
	if err != nil {
		tmpl, err1 := template.ParseFiles("./templates/login.html", "./templates/loginSignupForm.html")
		if err1 != nil {
			c.JSON(http.StatusInternalServerError, "could not parse template: " + err1.Error())
			return
		}
		_ = tmpl.Execute(c.Writer, Message{err.Error(), User{}})
		return
	}

	var signUpResponse *SignUpResponse
	err = json.NewDecoder(resp.Body).Decode(&signUpResponse)
	if err != nil {
		c.JSON(http.StatusInternalServerError, "could not parse response: " + err.Error())
	}

	u.tokens[signUpResponse.User.ID] = signUpResponse.Token

	tmpl, err1 := template.ParseFiles("./templates/displayProfile.html")
	if err1 != nil {
		c.JSON(http.StatusInternalServerError, "could not parse template: " + err1.Error())
		return
	}
	_ = tmpl.Execute(c.Writer, signUpResponse)

}

func (u *UserServer) GetSignup(c *gin.Context) {
	tmpl, err := template.ParseFiles("./templates/signup.html",  "./templates/loginSignupForm.html")
	if err != nil {
		c.JSON(http.StatusInternalServerError, "could not parse template: " + err.Error())
		return
	}
	err = tmpl.Execute(c.Writer, Form{Msg: "", Type: struct{ IsLogin bool }{IsLogin: false }})

	if err != nil {
		c.JSON(http.StatusInternalServerError, "could not execute template: " + err.Error())
		return
	}
}

func (u *UserServer) DisplayUser(c *gin.Context) {
	idString  := c.Param("id")
	id, err := strconv.Atoi(idString)
	token := u.tokens[uint64(id)]

	//getUser by Id
	r, err := http.NewRequest(http.MethodGet, u.apiAddr + "/user", nil)
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

	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, _ = ioutil.ReadAll(resp.Body)
	}
	// Restore the io.ReadCloser to its original state
	resp.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	var user *User
	err = json.Unmarshal(bodyBytes, &user)
	if err != nil {
		//unauthorized or user does not exist
		var msg string
		err1 := json.Unmarshal(bodyBytes, &msg)

		if err1 != nil {
			c.JSON(http.StatusInternalServerError, "could not parse response: " + err1.Error())
			return
		}

		tmpl, err1 := template.ParseFiles("./templates/login.html", "./templates/loginSignupForm.html")
		if err1 != nil {
			c.JSON(http.StatusInternalServerError, "could not parse template: " + err1.Error())
			return
		}

		_ = tmpl.Execute(c.Writer, Form{Msg: msg, Type: struct{ IsLogin bool }{IsLogin: true }})

		return

	}

	tmpl, err := template.ParseFiles("./templates/displayProfile.html")
	if err != nil {
		c.JSON(http.StatusInternalServerError, "could not parse template: " + err.Error())
		return
	}

	_ = tmpl.Execute(c.Writer, user)

}

func (u *UserServer) DisplayUserToEdit(c *gin.Context) {
	idString  := c.Param("id")
	id, err := strconv.Atoi(idString)
	token := u.tokens[uint64(id)]

	r, err := http.NewRequest(http.MethodGet, u.apiAddr + "/user", nil)
	fmt.Println(err)
	if err != nil {
		c.JSON(http.StatusInternalServerError, "could not make request for user info: " + err.Error())
		return
	}
	r.Header.Add("Authorization", token)

	resp, err := http.DefaultClient.Do(r)
	fmt.Println(err)
	if err != nil {
		c.JSON(http.StatusInternalServerError, "could not make request for user info: " + err.Error())
		return
	}

	var bodyBytes []byte
	if resp.Body != nil {
		bodyBytes, _ = ioutil.ReadAll(resp.Body)
	}
	// Restore the io.ReadCloser to its original state
	resp.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	var user *User
	err = json.Unmarshal(bodyBytes, &user)
	if err != nil {
		//unauthorized or user does not exist
		var msg string
		err1 := json.NewDecoder(resp.Body).Decode(&msg)

		if err1 != nil {
			c.JSON(http.StatusInternalServerError, "could not parse response: " + err1.Error())
			return
		}

		tmpl, err1 := template.ParseFiles("./templates/login.html", "./templates/loginSignupForm.html")
		if err1 != nil {
			c.JSON(http.StatusInternalServerError, "could not parse template: " + err1.Error())
			return
		}

		_ = tmpl.Execute(c.Writer, Form{Msg: msg, Type: struct{ IsLogin bool }{IsLogin: true }})

		return

	}

	tmpl, err := template.ParseFiles("./templates/editProfile.html")
	if err != nil {
		c.JSON(http.StatusInternalServerError, "could not parse template: " + err.Error())
		return
	}

	_ = tmpl.Execute(c.Writer, Message{Msg: "", User: *user})

}

func (u *UserServer) EditUser(c *gin.Context) {
	idString  := c.Param("id")
	id, err := strconv.Atoi(idString)
	token := u.tokens[uint64(id)]

	_ = c.Request.ParseForm()

	buff := new(bytes.Buffer)
	buff.Write([]byte("{"))
	for k, v := range c.Request.Form {
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

	req, err := http.NewRequest(http.MethodPut, u.apiAddr + "/user", buff)
	req.Header.Add("Authorization", token)

	resp, _ := http.DefaultClient.Do(req)

	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = ioutil.ReadAll(resp.Body)
	}
	// Restore the io.ReadCloser to its original state
	resp.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	var user *User
	err = json.Unmarshal(bodyBytes, &user)
	if err != nil {

		var msg string
		err1 := json.Unmarshal(bodyBytes, &msg)

		if err1 != nil {
			c.JSON(http.StatusInternalServerError, "could not parse response: " + err1.Error())
			return
		}

		tmpl, err1 := template.ParseFiles( "./templates/editProfile.html")
		if err1 != nil {
			c.JSON(http.StatusInternalServerError, "could not parse template: " + err1.Error())
			return
		}

		us := u.getUser(token)

		_ = tmpl.Execute(c.Writer, Message{Msg: msg, User: *us})

		return
	}

	us := u.getUser(token)

	tmpl, err := template.ParseFiles("./templates/displayProfile.html")
	if err != nil {
		c.JSON(http.StatusInternalServerError, "could not parse template: " + err.Error())
		return
	}

	_ = tmpl.Execute(c.Writer, us)

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