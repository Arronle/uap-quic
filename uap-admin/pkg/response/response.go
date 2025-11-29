package response

// Response 统一响应格式
type Response struct {
	Code int         `json:"code"`
	Data interface{} `json:"data,omitempty"`
	Msg  string      `json:"msg,omitempty"`
}

// Success 成功响应
func Success(data interface{}) Response {
	return Response{
		Code: 200,
		Data: data,
		Msg:  "",
	}
}

// Error 错误响应
func Error(code int, msg string) Response {
	return Response{
		Code: code,
		Data: nil,
		Msg:  msg,
	}
}

