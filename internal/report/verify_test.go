package report

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"
)

// signedReport arma un reporte firmado de punta a punta, igual que lo hace el
// agente, para que VerifyReport se pruebe contra el flujo real y no contra
// una cadena construida a mano.
func signedReport(t *testing.T, findings ...Finding) Report {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	chain := NewChain("nonce-de-prueba")
	for _, f := range findings {
		if _, err := chain.Append(f); err != nil {
			t.Fatal(err)
		}
	}
	return Report{
		Nonce:     "nonce-de-prueba",
		Pubkey:    hex.EncodeToString(pub),
		Findings:  findings,
		HashChain: chain.Hashes(),
		Signature: Sign(priv, chain.Root()),
	}
}

func TestVerifyReportAcceptsIntactReport(t *testing.T) {
	r := signedReport(t, fixedFinding("a"), fixedFinding("b"))
	if err := VerifyReport(r); err != nil {
		t.Fatalf("un reporte intacto debe verificar: %v", err)
	}
}

func TestVerifyReportAcceptsEmptyFindings(t *testing.T) {
	// Un escaneo LIMPIO no tiene hallazgos y aun así está firmado.
	if err := VerifyReport(signedReport(t)); err != nil {
		t.Fatalf("un reporte sin hallazgos debe verificar: %v", err)
	}
}

func TestVerifyReportDetectsEditedFinding(t *testing.T) {
	r := signedReport(t, fixedFinding("a"), fixedFinding("b"))
	r.Findings[1].Severity = "INFO" // alguien "bajó" un hallazgo a mano
	err := VerifyReport(r)
	if !errors.Is(err, ErrChainMismatch) {
		t.Fatalf("esperaba ErrChainMismatch, got %v", err)
	}
}

func TestVerifyReportDetectsRemovedFinding(t *testing.T) {
	r := signedReport(t, fixedFinding("a"), fixedFinding("b"))
	r.Findings = r.Findings[:1]
	if err := VerifyReport(r); !errors.Is(err, ErrChainMismatch) {
		t.Fatalf("esperaba ErrChainMismatch, got %v", err)
	}
}

func TestVerifyReportDetectsForeignSignature(t *testing.T) {
	r := signedReport(t, fixedFinding("a"))
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	r.Signature = Sign(otherPriv, r.HashChain[len(r.HashChain)-1])
	if err := VerifyReport(r); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("esperaba ErrBadSignature, got %v", err)
	}
}

func TestVerifyReportRequiresNonceAndPubkey(t *testing.T) {
	r := signedReport(t, fixedFinding("a"))
	r.Nonce = ""
	if err := VerifyReport(r); !errors.Is(err, ErrMissingNonce) {
		t.Fatalf("sin nonce: esperaba ErrMissingNonce, got %v", err)
	}
	r = signedReport(t, fixedFinding("a"))
	r.Pubkey = ""
	if err := VerifyReport(r); !errors.Is(err, ErrMissingPubkey) {
		t.Fatalf("sin pubkey: esperaba ErrMissingPubkey, got %v", err)
	}
}
