package ros_addrlist

type rosAddResponse struct {
	Ret string `json:"ret"`
}

type rosAdd400Response struct {
	Detail  string `json:"detail"`
	Error   int    `json:"error"`
	Message string `json:"message"`
}

type rosGetResponse struct {
	Id           string `json:".id"`
	Address      string `json:"address"`
	CreationTime string `json:"creation-time"`
	Disabled     string `json:"disabled"`
	Dynamic      string `json:"dynamic"`
	List         string `json:"list"`
	Timeout      string `json:"timeout"`
}
