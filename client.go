package ons

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

var (
	ErrRequestFail        = errors.New("请求失败")
	ErrAuthenticationFail = errors.New("鉴权失败")
	ErrRequestTimeout     = errors.New("请求超时")
)

type Client struct {
	URL        string
	SecretKey  string
	ProducerID string
	ConsumerID string
	httpClient *http.Client
	signature  hash.Hash
}

type ProducerResponse struct {
	MessageID  string `json:"msgId"`
	SendStatus string `json:"string"`
	Code       string `json:"code"`
	Info       string `json:"info"`
}

type Message struct {
	ID             string `json:"msgId"`
	Body           string `json:"body"`
	Handle         string `json:"msgHandle"`
	ReconsumeTimes int    `json:"reconsumeTimes"`
}

type ConsumerResponse struct {
	Code     string    `json:"code"`
	Info     string    `json:"info"`
	Messages []Message `json:"-"`
}

func (client *Client) SendMessage(topic, message string) (*ProducerResponse, error) {
	if client.httpClient == nil {
		client.httpClient = new(http.Client)
	}
	if client.signature == nil {
		client.signature = hmac.New(sha1.New, []byte(client.SecretKey))
	}
	timestamp := time.Now().Unix() * 1000
	url := fmt.Sprintf("%s?topic=%s&time=%d&tag=http&key=http",
		client.URL, url.QueryEscape(topic), timestamp)
	request, err := http.NewRequest("POST", url, bytes.NewBufferString(message))
	signString := fmt.Sprintf("%s\n%s\n%x\n%d",
		topic, client.ProducerID, md5.Sum([]byte(message)), timestamp)
	request.Header.Set("AccessKey", base64.StdEncoding.EncodeToString(client.signature.Sum([]byte(signString))))
	if err != nil {
		return nil, fmt.Errorf("创建HTTP请求出错: %s", err.Error())
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("发送HTTP请求出错: %s", err.Error())
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusCreated:
		content, _ := ioutil.ReadAll(response.Body)
		resp := new(ProducerResponse)
		if err := json.Unmarshal(content, resp); err != nil {
			return nil, fmt.Errorf("解析HTTP应答出错: status=%d, error=%s", response.StatusCode, err.Error())
		}
		return resp, nil
	case http.StatusBadRequest:
		content, _ := ioutil.ReadAll(response.Body)
		resp := new(ProducerResponse)
		if err := json.Unmarshal(content, resp); err != nil {
			return nil, fmt.Errorf("解析HTTP应答出错: status=%d, error=%s", response.StatusCode, err.Error())
		}
		return resp, ErrRequestFail
	case http.StatusForbidden:
		return nil, ErrAuthenticationFail
	case http.StatusRequestTimeout:
		return nil, ErrRequestTimeout
	}
	return nil, fmt.Errorf("未知应答状态: %d", response.StatusCode)
}

func (client *Client) ReceiveMessage(topic string, count int) (*ConsumerResponse, error) {
	if client.httpClient == nil {
		client.httpClient = new(http.Client)
	}
	if client.signature == nil {
		client.signature = hmac.New(sha1.New, []byte(client.SecretKey))
	}
	timestamp := time.Now().Unix() * 1000
	url := fmt.Sprintf("%s?topic=%s&time=%d&num=%d",
		client.URL, topic, timestamp, count)
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求出错: %s", err.Error())
	}
	signString := fmt.Sprintf("%s\n%s\n%d",
		topic, client.ConsumerID, timestamp)
	request.Header.Set("AccessKey", base64.StdEncoding.EncodeToString(client.signature.Sum([]byte(signString))))
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("发送HTTP请求出错: %s", err.Error())
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
		content, _ := ioutil.ReadAll(response.Body)
		var messages []Message
		if err := json.Unmarshal(content, &messages); err != nil {
			return nil, fmt.Errorf("解析HTTP应答出错: status=%d, error=%s", response.StatusCode, err.Error())
		}
		return &ConsumerResponse{
			Messages: messages,
		}, nil
	case http.StatusBadRequest:
		content, _ := ioutil.ReadAll(response.Body)
		resp := new(ConsumerResponse)
		if err := json.Unmarshal(content, resp); err != nil {
			return nil, fmt.Errorf("解析HTTP应答出错: status=%d, error=%s", response.StatusCode, err.Error())
		}
		return resp, ErrRequestFail
	case http.StatusForbidden:
		return nil, ErrAuthenticationFail
	case http.StatusRequestTimeout:
		return nil, ErrRequestTimeout
	}
	return nil, fmt.Errorf("未知应答状态: %d", response.StatusCode)
}
