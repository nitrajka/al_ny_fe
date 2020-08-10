package api

type Message struct {
	Msg string
	User User
}

type User struct {
	ID       uint64 `json:"id"`
	Username string `json:"username"`
	FullName string `json:"fullname"`
	Phone    string `json:"phone"`
	Address  string `json:"address"`
	IsGoogleRegistered bool `json:"registerGoogle"`
}

type UpdateUserBody struct {
	ID       uint64 `json:"id"`
	Username string `json:"username"`
	FullName string `json:"fullname"`
	Phone    string `json:"phone"`
	Address  string `json:"address"`
}

type SignUpResponse struct {
	Token string 	`json:"token"`
	User User 		`json:"user"`
}

type Form struct {
	Msg string
	Type struct { IsLogin bool}
}
