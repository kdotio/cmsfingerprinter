package fingerprinter

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"cms-fingerprinter/helpers"
)

type testcaseOffline struct {
	expectedTags []string
	offlineHttp  map[string]string
}

func TestOffline(t *testing.T) {
	cases := []struct {
		cms      string
		testdata testcaseOffline
	}{
		// offline testdata is based on actual online cms sites
		// for files that returned 200 status code and thus could be hashed
		{cms: "shopware5", testdata: testShopware5()},
		{cms: "laravel", testdata: testLaravel()},
		{cms: "opencart", testdata: testOpenCart()},
		{cms: "drupal", testdata: testDrupal()},
		{cms: "joomla", testdata: testJoomla()},
		{cms: "typo3", testdata: testTypo3()},
		{cms: "wordpress", testdata: testWordpress()},
	}

	const testcase = "http://example.local"
	// const hashes = "../hashes/wordpress.json"

	for _, tc := range cases {
		t.Run(tc.cms, func(t *testing.T) {

			bytes, err := os.ReadFile(fmt.Sprintf("../hashes/%s.json", tc.cms))
			if err != nil {
				log.Fatal(err)
			}

			f, err := NewFingerprinter(bytes)
			if err != nil {
				t.Fatal(err)
			}

			// override http requester+hasher for test purposes
			f.requestHash = testHttpRequester(testcase, tc.testdata.offlineHttp)

			f.httpRequestDelay = 0

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			_, tag, err := f.Analyze(ctx, testcase)
			if err != nil {
				t.Fatal(err)
			}

			if !helpers.AreEqual(tc.testdata.expectedTags, tag) {
				t.Fatalf("expected %s, got %s", tc.testdata.expectedTags, tag)
			}

			t.Log("Final tag:", tag)
		})
	}
}

func testHttpRequester(mockTarget string, sCodes map[string]string) httpHashRequester {
	return func(_ context.Context, target string) (md5sum string, sCode int, err error) {
		uri := strings.TrimPrefix(target, mockTarget)

		if hash, ok := sCodes[uri]; ok {
			log.Printf("(%d) %s\n", 200, target)
			return hash, 200, nil
		}

		log.Printf("(%d) %s\n", 404, target)
		return "", 404, nil
	}
}

func testShopware5() testcaseOffline {
	return testcaseOffline{[]string{"5.6.9"}, map[string]string{
		"/themes/Backend/ExtJs/backend/article/controller/detail.js":                    "0ba7f745902727dd546ce2cc46f1e78c",
		"/themes/Frontend/Responsive/frontend/_public/src/js/jquery.csrf-protection.js": "858d0272edeb4f244f33fe88740b252c",
		"/themes/Backend/ExtJs/backend/order/view/list/filter.js":                       "88430f760329e995191f86aac156f9f7",
		"/license.txt": "aa0310990da92ad9407dee82039b0ed5",
		"/engine/Shopware/Components/DependencyInjection/services.xml": "3a30a7e159ae5b44a015f6bee5b923cf",
	}}
}

func testLaravel() testcaseOffline {
	return testcaseOffline{[]string{"5.6.21", "5.6.12", "5.6.7", "5.6.0"}, map[string]string{
		"/robots.txt": "b6216d61c03e6ce0c9aea6ca7808f7ca",
		"/js/app.js":  "37fa6f83bcff373325438a9fdcb8b77c",
	}}
}

func testOpenCart() testcaseOffline {
	return testcaseOffline{[]string{"2.0.3.1", "2.0.3.0"}, map[string]string{
		"/catalog/view/theme/default/stylesheet/stylesheet.css":         "88967a1821c3f145cb83106d1f0a239c",
		"/catalog/view/javascript/common.js":                            "f5bfe719763e685c6c98f30cf8dbba36",
		"/catalog/view/javascript/jquery/owl-carousel/owl.carousel.css": "6df9137a72146204b17f03467056095c",
	}}
}

func testDrupal() testcaseOffline {
	return testcaseOffline{[]string{"9.1.4"}, map[string]string{
		"/core/MAINTAINERS.txt": "24d955bc3a5d3a30d4d1e8ae603f6bd5",
	}}
}

func testJoomla() testcaseOffline {
	return testcaseOffline{[]string{"3.9.21"}, map[string]string{
		"/administrator/manifests/files/joomla.xml": "e0364b642f5eeb4b8b624d0510e56d3e",
	}}
}

func testTypo3() testcaseOffline {
	return testcaseOffline{[]string{"8.7.32"}, map[string]string{
		"/typo3/sysext/backend/Resources/Public/Css/backend.css":          "81932b9d6616b50ac93669b465535d2b",
		"/typo3/sysext/backend/Resources/Public/JavaScript/FormEngine.js": "8b5efa4095433e28d704b7c1bdcd2594",
	}}
}

func testWordpress() testcaseOffline {
	return testcaseOffline{[]string{"5.8.4"}, map[string]string{
		"/readme.html":                          "5c5fb2fc92934133f676ab414579b55b",
		"/wp-includes/css/media-views-rtl.css":  "071a0f3a8cb7d790ce3b5cb4a9e8e8de",
		"/wp-includes/js/dist/block-library.js": "1ed4effc0f532ace2602e456a6279c15",
	}}
}
