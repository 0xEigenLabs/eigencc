package teesdk

type TrustClient interface {
	Ecall(method string, cipher string) (string, error)
}
