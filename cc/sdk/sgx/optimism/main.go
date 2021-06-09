package main

import (
    "io/ioutil"

    "gopkg.in/yaml.v2"
    "github.com/ieigen/teesdk/sgx"
)

var (
	client  *sgx.TEEClient
	tconfig *sgx.TEEConfig
)

func loadConfigFile(configPath string) (*sgx.TEEConfig, error) {
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var nc sgx.TEEConfig
	if err := yaml.Unmarshal(data, &nc); err != nil {
		return nil, err
	}
	return &nc, nil
}


func Init(confPath string) error {
	cfg, err := loadConfigFile(confPath)
	if err != nil {
		return err
	}
	tconfig = cfg
	client = sgx.NewTEEClient(cfg.Uid,
		cfg.Token,
		cfg.Auditors[0].PublicDer,
		cfg.Auditors[0].Sign,
		cfg.Auditors[0].EnclaveInfoConfig,
		cfg.TMSPort)
	return nil
}

func Ecall(requestBuf []byte) ([]byte, error) {
	return requestBuf, nil
}

func main() {}
