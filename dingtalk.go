package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type DingTalk struct {
	InternalUrl string   //dingtalk 内网地址
	PublicUrl   string   //dingtalk 外网地址
	App         string   // app 名称
	Admins      []string // 管理员
	Secret      string   // 密钥
	httpClient  *http.Client
}

var (
	Dc         DingTalk
	TokenCatch *TTLCache
)

func Init(client DingTalk) {
	Dc = client
	Dc.httpClient = http.DefaultClient
	TokenCatch = NewTTL()
}

func (d *DingTalk) QRUrl(redirect string) string {
	uri := d.PublicUrl + "/qr_login"
	var q = url.Values{}
	q.Add("app_name", d.App)
	q.Add("callback", redirect)
	return uri + "?" + q.Encode()
}

type User struct {
	Active  bool
	Admin   bool
	Avatar  string
	Mobile  string
	Name    string
	Title   string
	UserID  string
	IsAdmin bool
}

// UserInfo 根据登录的code获取用户信息
func (d *DingTalk) UserInfo(ctx context.Context, code, codeType string) (*User, error) {
	var (
		q   = url.Values{}
		req *http.Request
		err error
	)
	var user User
	if codeType == "mobile" {
		q.Add("mobile", code)
		req, err = d.buildRequest(ctx, "/user/info", q, nil)
		if err != nil {
			return nil, err
		}
		if err = d.do(req, &user); err != nil {
			return nil, err
		}
	} else {
		q.Add("code", code)
		req, err = d.buildRequest(ctx, "/qr_login/user_info", q, nil)
		if err != nil {
			return nil, err
		}
		var ret struct {
			User User
		}
		if err = d.do(req, &ret); err != nil {
			return nil, err
		}
		user = ret.User
	}

	for _, v := range d.Admins {
		if v == user.Mobile {
			user.IsAdmin = true
			break
		}
	}
	return &user, nil
}

type ResultResponse struct {
	Message string
	Data    interface{}
}

func (d *DingTalk) do(req *http.Request, ret interface{}) error {
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	s, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	response := &ResultResponse{
		Data: ret,
	}
	if err := json.Unmarshal(s, response); err != nil {
		return err
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return nil
	}
	return errors.New(response.Message)
}

func (d *DingTalk) buildRequest(ctx context.Context, path string, q url.Values, body interface{}) (*http.Request, error) {
	q.Set("timestamp", fmt.Sprintf("%d", time.Now().Unix()))
	q.Set("app_name", d.App)
	uri := d.InternalUrl + path + "?" + q.Encode()

	var req *http.Request
	var err error
	if body == nil {
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	} else {
		b, _ := json.Marshal(body)
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, uri, bytes.NewBuffer(b))
	}
	if err != nil {
		return nil, err
	}
	s := d.sign(q)
	req.Header.Set("X-Token", s)
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

func (d *DingTalk) sign(q url.Values) string {
	q.Set("timestamp", fmt.Sprintf("%d", time.Now().Unix()))
	q.Set("app_name", d.App)

	// 获取所有Uri Parameters
	stringSlice := make([]string, 0)
	for k := range q {
		// 放入string 数组
		stringSlice = append(stringSlice, k)
	}
	// 对所有请求参数进行字典升序排列；
	sort.Strings(stringSlice)
	var tokenTmp string
	for _, v := range stringSlice {
		// 将以上排序后的参数表进行字符串连接，如key1value1key2value2key3value3...keyNvalueN；
		tokenTmp += v + q.Get(v)
	}
	// app secret作为后缀，对该字符串进行SHA-1计算，并转换成16进制编码；
	tokenTmp = tokenTmp + d.Secret
	crypt := sha1.New()
	crypt.Write([]byte(tokenTmp))
	tmp := hex.EncodeToString(crypt.Sum(nil))
	// 转换为全大写形式后即获得签名串

	return strings.ToUpper(tmp)
}
