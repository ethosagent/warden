package httpc

import "net/http"

func Get() { http.Get("https://x") }

func Do() { http.DefaultClient.Do(nil) }

func New() *http.Client { return &http.Client{} }
