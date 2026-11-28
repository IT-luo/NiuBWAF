package certmgr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const masterKeyFile = "dns-certificates.key"

func (m *Manager) keyCipher(create bool) (cipher.AEAD, error) {
	path := filepath.Join(m.dataDir, masterKeyFile)
	key, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && create {
		var accounts int
		if err := m.db.QueryRow("SELECT count(*) FROM dns_certificate_accounts").Scan(&accounts); err != nil {
			return nil, err
		}
		if accounts != 0 {
			return nil, errors.New("托管证书密钥文件缺失，请从备份恢复")
		}
		if err := createMasterKey(path); err != nil {
			return nil, err
		}
		key, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, fmt.Errorf("读取托管证书密钥文件: %w", err)
	}
	if len(key) != 32 {
		return nil, errors.New("托管证书密钥文件长度无效")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func createMasterKey(path string) error {
	var key [32]byte
	rand.Read(key[:])
	file, err := os.CreateTemp(filepath.Dir(path), ".dns-cert-key-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(key[:]); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	// Publish the complete key without replacing a key from another worker.
	if err := os.Link(file.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return nil
}

func (m *Manager) seal(plain []byte, label string, create bool) ([]byte, error) {
	aead, err := m.keyCipher(create)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nil, plain, []byte(label)), nil
}

func (m *Manager) open(data []byte, label string) ([]byte, error) {
	aead, err := m.keyCipher(false)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nil, data, []byte(label))
	if err != nil {
		return nil, errors.New("无法解密托管证书凭据，请检查密钥文件是否匹配")
	}
	return plain, nil
}
