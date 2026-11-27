// refverify checks AMD SEV-SNP and Intel TDX evidence with Google's reference
// verifiers (go-sev-guest, go-tdx-guest), offline, for the differential tests
// of Anagram's verifiers (tests/test_enclave_differential.py).
//
// It reads one JSON request per line on stdin and writes one JSON verdict per
// line on stdout: {"id": ..., "ok": true|false, "err": "..."}. The CRLs and
// Intel's collateral come from the request (a getter serves them by URL), and
// the trusted roots are the pinned ones the request names.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/go-sev-guest/abi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	sevverify "github.com/google/go-sev-guest/verify"
	sevtrust "github.com/google/go-sev-guest/verify/trust"
	tdxabi "github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/pcs"
	tdxverify "github.com/google/go-tdx-guest/verify"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type request struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Now  int64  `json:"now"`
	// SNP
	Product  string `json:"product"`
	Stepping uint32 `json:"stepping"`
	Report   string `json:"report"`
	Leaf     string `json:"leaf"`
	Ask      string `json:"ask"`
	Ark      string `json:"ark"`
	Crl      string `json:"crl"`
	PinAsk   string `json:"pin_ask"`
	PinArk   string `json:"pin_ark"`
	// TDX
	Quote      string `json:"quote"`
	TcbInfo    string `json:"tcb_info"`
	QeIdentity string `json:"qe_identity"`
	TcbSigning string `json:"tcb_signing"`
	RootCrl    string `json:"root_crl"`
	PckCrl     string `json:"pck_crl"`
	Root       string `json:"root"`
	PckCa      string `json:"pck_ca"`
}

type verdict struct {
	ID  string `json:"id"`
	Ok  bool   `json:"ok"`
	Err string `json:"err,omitempty"`
}

func b64(s string) []byte {
	out, _ := base64.StdEncoding.DecodeString(s)
	return out
}

func pemOf(der ...[]byte) string {
	var b strings.Builder
	for _, d := range der {
		b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d}))
	}
	return b.String()
}

// sevGetter serves the AMD CRL for any KDS CRL URL.
type sevGetter struct{ crl []byte }

func (g sevGetter) Get(u string) ([]byte, error) {
	if strings.HasSuffix(u, "/crl") {
		return g.crl, nil
	}
	return nil, fmt.Errorf("offline: no %s", u)
}

// tdxGetter serves Intel PCS responses from the request, with the issuer
// chain headers PCS would send.
type tdxGetter struct{ r request }

func (g tdxGetter) Get(u string) (map[string][]string, []byte, error) {
	root := b64(g.r.Root)
	signing := url.QueryEscape(pemOf(b64(g.r.TcbSigning), root))
	switch {
	case strings.Contains(u, "/tcb?"):
		return map[string][]string{pcs.TcbInfoIssuerChainPhrase: {signing}}, b64(g.r.TcbInfo), nil
	case strings.Contains(u, "/qe/identity"):
		return map[string][]string{pcs.SgxQeIdentityIssuerChainPhrase: {signing}}, b64(g.r.QeIdentity), nil
	case strings.Contains(u, "pckcrl"):
		chain := url.QueryEscape(pemOf(b64(g.r.PckCa), root))
		return map[string][]string{pcs.SgxPckCrlIssuerChainPhrase: {chain}}, b64(g.r.PckCrl), nil
	case strings.Contains(u, "RootCA") || strings.HasSuffix(u, ".crl") || strings.Contains(u, "crl"):
		return map[string][]string{}, b64(g.r.RootCrl), nil
	}
	return nil, nil, fmt.Errorf("offline: no %s", u)
}

func checkSnp(r request) error {
	report, err := abi.ReportToProto(b64(r.Report))
	if err != nil {
		return err
	}
	att := &spb.Attestation{
		Report: report,
		CertificateChain: &spb.CertificateChain{
			VcekCert: b64(r.Leaf), AskCert: b64(r.Ask), ArkCert: b64(r.Ark),
		},
	}
	names := map[string]spb.SevProduct_SevProductName{
		"Milan": spb.SevProduct_SEV_PRODUCT_MILAN,
		"Genoa": spb.SevProduct_SEV_PRODUCT_GENOA,
		"Turin": spb.SevProduct_SEV_PRODUCT_TURIN,
	}
	name, ok := names[r.Product]
	if !ok {
		return fmt.Errorf("unknown product %q", r.Product)
	}
	root := sevtrust.AMDRootCertsProduct(r.Product)
	if err := root.Decode(b64(r.PinAsk), b64(r.PinArk)); err != nil {
		return fmt.Errorf("pinned roots: %v", err)
	}
	opts := &sevverify.Options{
		CheckRevocations:    true,
		DisableCertFetching: true,
		Getter:              sevGetter{b64(r.Crl)},
		Now:                 time.Unix(r.Now, 0),
		TrustedRoots:        map[string][]*sevtrust.AMDRootCerts{r.Product: {root}},
		Product:             &spb.SevProduct{Name: name, MachineStepping: wrapperspb.UInt32(r.Stepping)},
	}
	return sevverify.SnpAttestation(att, opts)
}

func checkTdx(r request) error {
	quote, err := tdxabi.QuoteToProto(b64(r.Quote))
	if err != nil {
		return err
	}
	now := time.Unix(r.Now, 0)
	opts := &tdxverify.Options{
		CheckRevocations:      true,
		GetCollateral:         true,
		Getter:                tdxGetter{r},
		Now:                   &tdxverify.TimeSet{PckCertChain: now, TcbInfo: now, QeIdentity: now, RootCaCrl: now, PckCrl: now},
		DisableTcbStatusCheck: true, // rule 8 only: the TCB status is rule 2
	}
	return tdxverify.TdxQuote(quote, opts)
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 64<<20)
	// Only verdicts go to stdout. go-tdx-guest points the shared logger at
	// file 1 when it loads, so the verdicts get a copy of file 1, and file 1
	// becomes stderr.
	fd, err := unix.Dup(1)
	if err != nil || unix.Dup2(2, 1) != nil {
		fmt.Fprintln(os.Stderr, "cannot move stdout:", err)
		os.Exit(1)
	}
	out := json.NewEncoder(os.NewFile(uintptr(fd), "verdicts"))
	for in.Scan() {
		var r request
		v := verdict{}
		if err := json.Unmarshal(in.Bytes(), &r); err != nil {
			v.Err = "request: " + err.Error()
		} else {
			v.ID = r.ID
			var err error
			func() {
				defer func() {
					if p := recover(); p != nil {
						err = fmt.Errorf("panic: %v", p)
					}
				}()
				switch r.Kind {
				case "snp":
					err = checkSnp(r)
				case "tdx":
					err = checkTdx(r)
				default:
					err = fmt.Errorf("unknown kind %q", r.Kind)
				}
			}()
			v.Ok = err == nil
			if err != nil {
				v.Err = err.Error()
			}
		}
		if err := out.Encode(v); err != nil {
			os.Exit(1)
		}
	}
}
