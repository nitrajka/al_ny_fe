package api

type User struct {
	ID                 uint64 `json:"id"`
	Username           string `json:"username"`
	FullName           string `json:"fullname"`
	Phone              string `json:"phone"`
	Address            string `json:"address"`
	IsGoogleRegistered bool   `json:"registerGoogle"`
}

type UpdateUserBody struct {
	Username string `json:"username"`
	FullName string `json:"fullname"`
	Phone    string `json:"phone"`
	Address  string `json:"address"`
}

type SignUpResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

type Template struct {
	Msg        string
	Type       *struct{ IsLogin bool }
	User       *User
	Token      string
	Mail       string
	ValidToken bool
}

func (t *Template) Set(msg string, user *User, typ *struct{ IsLogin bool }) {
	t.Msg = msg
	t.User = user
	t.Type = typ
}

func (t *Template) Reset() {
	t.Msg = ""
	t.User = nil
	t.Type = nil
	t.Token = ""
	t.Mail = ""
	t.ValidToken = false
}

func (t *Template) AddMessage(msg string) {
	if t.Msg != "" {
		t.Msg += "\n"
	}

	t.Msg += msg
}