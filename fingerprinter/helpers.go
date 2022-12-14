package fingerprinter

import (
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func md5hash(s string) string {
	data := []byte(s)
	return fmt.Sprintf("%x", md5.Sum(data))
}

func isImage(file string) bool {
	for _, ending := range []string{".jpeg", ".jpg", ".gif", ".png"} {
		if strings.HasSuffix(file, ending) {
			return true
		}
	}

	return false
}

type httpHashRequester func(ctx context.Context, target string) (md5sum string, sCode int, err error)

func defaultHttpHasher(client *http.Client) httpHashRequester {
	return func(ctx context.Context, target string) (md5sum string, sCode int, err error) {
		body, sCode, err := httpRequest(ctx, client, target)
		if err != nil {
			return "", 0, err
		}

		if sCode != 200 {
			return "", sCode, nil
		}

		// if strings.Contains(body, "\r") {
		// 	fmt.Println(`Has \r in document`)
		// }

		// if strings.Contains(body, "\r\n") {
		// 	fmt.Println(`Has \r\n in document`)
		// }

		// skip trimming all \r in body, if mimetype is of image: jpg, png, gif
		if !isImage(target) {
			// convert to UNIX style, as some admins may convert files to DOS style during upload
			body = strings.ReplaceAll(body, "\r", "")
		}

		// if strings.Contains(body, "\r") {
		// 	fmt.Println(`Has \r in document`)
		// }

		// if strings.HasSuffix(body, "\n") {
		//	fmt.Println(`Has \n at body end`)
		//}
		//body = strings.TrimSuffix(body, "\n") // sometimes \r\n is added to file end, without trim no match can be made

		hash := md5hash(body)
		return hash, 200, nil
	}
}

func httpRequest(ctx context.Context, client *http.Client, target string) (body string, sCode int, err error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return "", 0, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; CrOS i686 2268.111.0) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.57 Safari/536.11")

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, err
	}

	return string(bytes), resp.StatusCode, nil
}
