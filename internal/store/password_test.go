package store

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestPBKDF2SHA256KnownVectors(t *testing.T) {
	cases := []struct {
		iter int
		want string
	}{
		{1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
		{2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
		{4096, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
	}
	for _, c := range cases {
		got := hex.EncodeToString(pbkdf2SHA256([]byte("password"), []byte("salt"), c.iter, 32))
		if got != c.want {
			t.Fatalf("iter=%d\n got %s\nwant %s", c.iter, got, c.want)
		}
	}
}

func TestHashPassRoundTrip(t *testing.T) {
	h := HashPass("s3cret-pass")
	if !strings.HasPrefix(h, "pbkdf2_sha256$") {
		t.Fatalf("哈希格式异常: %s", h)
	}
	if ok, rehash := VerifyPass("s3cret-pass", h); !ok || rehash {
		t.Fatalf("正确口令应通过且无需升级, ok=%v rehash=%v", ok, rehash)
	}
	if ok, _ := VerifyPass("wrong", h); ok {
		t.Fatal("错误口令不应通过")
	}
	if HashPass("s3cret-pass") == h {
		t.Fatal("随机盐应使两次哈希不同")
	}
}

func TestVerifyPassLegacyCompat(t *testing.T) {
	legacy := legacyHash("admin123")
	ok, rehash := VerifyPass("admin123", legacy)
	if !ok || !rehash {
		t.Fatalf("旧哈希应兼容且标记升级, ok=%v rehash=%v", ok, rehash)
	}
	if ok, _ := VerifyPass("bad", legacy); ok {
		t.Fatal("旧哈希错误口令不应通过")
	}
}

func TestVerifyPassMalformed(t *testing.T) {
	for _, s := range []string{"", "pbkdf2_sha256$abc$zz$yy", "pbkdf2_sha256$0$salt$hash", "pbkdf2_sha256$100$$"} {
		if ok, _ := VerifyPass("x", s); ok {
			t.Fatalf("畸形存储不应通过: %q", s)
		}
	}
}
