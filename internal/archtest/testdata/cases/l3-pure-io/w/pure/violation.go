package pure

import (
	"net/http"
	"time"
)

var _ = http.StatusOK

func Check() bool { return time.Now().Before(time.Time{}) }
