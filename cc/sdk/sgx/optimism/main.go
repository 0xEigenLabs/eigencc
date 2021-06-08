package main

import (
	"encoding/json"
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
	var (
		err       error
		tmpbuf    []byte
		tmpbufstr string
		plainMap  map[string]string
	)
	in := &pb.TrustFunctionCallRequest{}
	if err = proto.Unmarshal(requestBuf, in); err != nil {
		return nil, err
	}
	if tconfig == nil || !tconfig.Enable || client == nil {
		err = fmt.Errorf("IsTFCEnabled is false, this node doest not enable TEE")
		return nil, err
	}
	if tmpbuf, err = json.Marshal(sgx.FuncCaller{
		Method: in.Method, Args: in.Args, Svn: in.Svn,
		Address: in.Address, PublicKey: in.PublicKey,
		Signature: in.Signature}); err != nil {
		return nil, err
	}
	if tmpbufstr, err = client.Submit("xchaintf", string(tmpbuf)); err != nil {
		return nil, err
	}
	if err = json.Unmarshal([]byte(tmpbufstr), &plainMap); err != nil {
		return nil, err
	}
	kvs := &pb.TrustFunctionCallResponse_Kvs{
		Kvs: &pb.KVPairs{},
	}
	for k, v := range plainMap {
		kvs.Kvs.Kv = append(kvs.Kvs.Kv, &pb.KVPair{Key: k, Value: v})
	}
	return proto.Marshal(&pb.TrustFunctionCallResponse{Results: kvs})
}

func main() {}
