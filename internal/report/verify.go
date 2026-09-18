package report

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
)

// Errores de verificación. Se distinguen para que quien revisa sepa QUÉ
// falló: no es lo mismo un reporte editado a mano que uno firmado con otra
// clave.
var (
	ErrMissingNonce  = errors.New("el reporte no trae nonce: no se puede recomputar la cadena")
	ErrMissingPubkey = errors.New("el reporte no trae clave pública: no se puede verificar la firma")
	ErrChainMismatch = errors.New("la cadena de hashes no coincide con los hallazgos: el reporte fue alterado")
	ErrBadSignature  = errors.New("la firma no verifica contra la clave pública del reporte")
)

// VerifyReport recomputa la cadena de custodia a partir del nonce y los
// hallazgos y valida la firma Ed25519 sobre el root. Es lo que permite que un
// tercero, sin servidor, compruebe que un reporte.json no fue editado después
// de generarse.
//
// Lo que NO prueba: que el reporte lo haya generado este agente sobre esa
// máquina. La clave es efímera por sesión, así que la firma ata el contenido
// a la clave, no la clave a nadie. Eso solo lo da un servidor que registre la
// clave al abrir la sesión.
func VerifyReport(r Report) error {
	if r.Nonce == "" {
		return ErrMissingNonce
	}
	if r.Pubkey == "" {
		return ErrMissingPubkey
	}
	pub, err := hex.DecodeString(r.Pubkey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: clave inválida", ErrMissingPubkey)
	}

	chain := NewChain(r.Nonce)
	for i, f := range r.Findings {
		if _, err := chain.Append(f); err != nil {
			return fmt.Errorf("hallazgo %d (%s): %w", i, f.ID, err)
		}
	}
	got := chain.Hashes()
	if len(got) != len(r.HashChain) {
		return fmt.Errorf("%w: %d hashes recomputados, %d en el reporte", ErrChainMismatch, len(got), len(r.HashChain))
	}
	for i := range got {
		if got[i] != r.HashChain[i] {
			return fmt.Errorf("%w (posición %d)", ErrChainMismatch, i)
		}
	}
	if !Verify(ed25519.PublicKey(pub), chain.Root(), r.Signature) {
		return ErrBadSignature
	}
	return nil
}
