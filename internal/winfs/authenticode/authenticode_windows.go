//go:build windows

package authenticode

import (
	"encoding/hex"
	"errors"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wintrust = windows.NewLazySystemDLL("wintrust.dll")
	crypt32  = windows.NewLazySystemDLL("crypt32.dll")

	procCryptCATAdminAcquireContext2        = wintrust.NewProc("CryptCATAdminAcquireContext2")
	procCryptCATAdminReleaseContext         = wintrust.NewProc("CryptCATAdminReleaseContext")
	procCryptCATAdminCalcHashFromFileHandle = wintrust.NewProc("CryptCATAdminCalcHashFromFileHandle2")
	procCryptCATAdminEnumCatalogFromHash    = wintrust.NewProc("CryptCATAdminEnumCatalogFromHash")
	procCryptCATAdminReleaseCatalogContext  = wintrust.NewProc("CryptCATAdminReleaseCatalogContext")
	procCryptCATCatalogInfoFromContext      = wintrust.NewProc("CryptCATCatalogInfoFromContext")
	procCryptMsgGetParam                    = crypt32.NewProc("CryptMsgGetParam")
	procCryptMsgClose                       = crypt32.NewProc("CryptMsgClose")
)

// driverActionVerify es el subsistema de catálogos de drivers
// ({F750E6C3-38EE-11d1-85E5-00C04FC295EE}); cubre también los catálogos de
// componentes de Windows.
var driverActionVerify = windows.GUID{
	Data1: 0xF750E6C3, Data2: 0x38EE, Data3: 0x11D1,
	Data4: [8]byte{0x85, 0xE5, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE},
}

// winTrustCatalogInfo es WINTRUST_CATALOG_INFO (wintrust.h), que x/sys no
// declara. Layout de 64 bits con los paddings explícitos.
type winTrustCatalogInfo struct {
	Size               uint32
	CatalogVersion     uint32
	CatalogFilePath    *uint16
	MemberTag          *uint16
	MemberFilePath     *uint16
	MemberFile         windows.Handle
	CalculatedFileHash *byte
	CalculatedHashSize uint32
	_                  uint32
	CatalogContext     uintptr
	CatAdmin           uintptr
}

// catalogInfo es CATALOG_INFO: cbStruct + wszCatalogFile[MAX_PATH].
type catalogInfo struct {
	Size        uint32
	CatalogFile [windows.MAX_PATH]uint16
}

const cmsgSignerInfoParam = 6

// verifyFile es la implementación real de Verify.
func verifyFile(path string) Result {
	if _, err := os.Stat(path); err != nil {
		return Result{Status: StatusUnknown, Detail: "no se pudo acceder al archivo: " + err.Error()}
	}
	err := verifyEmbedded(path)
	switch {
	case err == nil:
		r := Result{Status: StatusSigned}
		r.Signer = embeddedSigner(path)
		return r
	case isErrno(err, windows.TRUST_E_NOSIGNATURE):
		// Sin firma embebida: puede estar en un catálogo (así vienen casi
		// todos los binarios de Windows y los drivers WHQL).
		return verifyCatalog(path)
	default:
		return classifyFailure(err)
	}
}

// verifyEmbedded corre WinVerifyTrust sobre la firma embebida del archivo.
func verifyEmbedded(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	data := &windows.WinTrustData{
		Size:             uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:         windows.WTD_UI_NONE,
		RevocationChecks: windows.WTD_REVOKE_NONE,
		UnionChoice:      windows.WTD_CHOICE_FILE,
		StateAction:      windows.WTD_STATEACTION_VERIFY,
		// Sin red: una verificación que cuelga esperando una CRL en la PC de
		// un jugador sin internet es peor que no revisar revocación.
		ProvFlags: windows.WTD_CACHE_ONLY_URL_RETRIEVAL | windows.WTD_REVOCATION_CHECK_NONE,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&windows.WinTrustFileInfo{
			Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
			FilePath: p,
		}),
	}
	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	return verifyErr
}

// verifyCatalog busca el hash del archivo en los catálogos del sistema y, si
// aparece, verifica la firma del catálogo con el archivo como miembro.
func verifyCatalog(path string) Result {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return Result{Status: StatusUnknown, Detail: err.Error()}
	}
	file, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return Result{Status: StatusUnknown, Detail: "abrir para catálogo: " + err.Error()}
	}
	defer windows.CloseHandle(file)

	// Los catálogos modernos indexan por SHA-256; los viejos, por SHA-1. Se
	// prueba en ese orden y se acepta el primero que encuentre el archivo.
	for _, alg := range []string{"SHA256", "SHA1"} {
		found, r := lookupCatalog(alg, p, file)
		if found {
			return r
		}
	}
	return Result{Status: StatusUnsigned}
}

// lookupCatalog hace la búsqueda con un algoritmo de hash. found es false si
// ningún catálogo contiene el archivo (y r no significa nada).
func lookupCatalog(hashAlg string, path *uint16, file windows.Handle) (found bool, r Result) {
	algPtr, _ := windows.UTF16PtrFromString(hashAlg)
	var catAdmin uintptr
	ret, _, _ := procCryptCATAdminAcquireContext2.Call(
		uintptr(unsafe.Pointer(&catAdmin)),
		uintptr(unsafe.Pointer(&driverActionVerify)),
		uintptr(unsafe.Pointer(algPtr)), 0, 0)
	if ret == 0 || catAdmin == 0 {
		return false, Result{}
	}
	defer procCryptCATAdminReleaseContext.Call(catAdmin, 0)

	// Primera llamada: tamaño del hash. Segunda: el hash.
	var hashSize uint32
	procCryptCATAdminCalcHashFromFileHandle.Call(catAdmin, uintptr(file),
		uintptr(unsafe.Pointer(&hashSize)), 0, 0)
	if hashSize == 0 || hashSize > 64 {
		return false, Result{}
	}
	hash := make([]byte, hashSize)
	ret, _, _ = procCryptCATAdminCalcHashFromFileHandle.Call(catAdmin, uintptr(file),
		uintptr(unsafe.Pointer(&hashSize)), uintptr(unsafe.Pointer(&hash[0])), 0)
	if ret == 0 {
		return false, Result{}
	}

	catInfoCtx, _, _ := procCryptCATAdminEnumCatalogFromHash.Call(catAdmin,
		uintptr(unsafe.Pointer(&hash[0])), uintptr(hashSize), 0, 0)
	if catInfoCtx == 0 {
		return false, Result{}
	}
	defer procCryptCATAdminReleaseCatalogContext.Call(catAdmin, catInfoCtx, 0)

	var info catalogInfo
	info.Size = uint32(unsafe.Sizeof(info))
	ret, _, _ = procCryptCATCatalogInfoFromContext.Call(catInfoCtx, uintptr(unsafe.Pointer(&info)), 0)
	if ret == 0 {
		return false, Result{}
	}

	// El member tag es el hash en hexadecimal mayúsculas, como lo indexa el
	// catálogo.
	tag, _ := windows.UTF16PtrFromString(upperHex(hash))
	catPath := &info.CatalogFile[0]
	wci := &winTrustCatalogInfo{
		Size:               uint32(unsafe.Sizeof(winTrustCatalogInfo{})),
		CatalogFilePath:    catPath,
		MemberTag:          tag,
		MemberFilePath:     path,
		MemberFile:         file,
		CalculatedFileHash: &hash[0],
		CalculatedHashSize: hashSize,
		CatAdmin:           catAdmin,
	}
	data := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_CATALOG,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		ProvFlags:                       windows.WTD_CACHE_ONLY_URL_RETRIEVAL | windows.WTD_REVOCATION_CHECK_NONE,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(wci),
	}
	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	if verifyErr == nil {
		return true, Result{Status: StatusSigned, Catalog: true, Signer: "Microsoft Windows (catálogo)"}
	}
	r = classifyFailure(verifyErr)
	r.Catalog = true
	return true, r
}

// classifyFailure traduce el HRESULT de WinVerifyTrust a un Status. Los
// códigos que implican "hay firma y está mal" van a invalid; el resto, a
// unknown: no se puede acusar a nadie por un error de la API.
func classifyFailure(err error) Result {
	invalid := []windows.Handle{
		windows.TRUST_E_BAD_DIGEST,
		windows.TRUST_E_SUBJECT_NOT_TRUSTED,
		windows.TRUST_E_EXPLICIT_DISTRUST,
		windows.CERT_E_UNTRUSTEDROOT,
		windows.CERT_E_REVOKED,
		windows.CERT_E_CHAINING,
		windows.CERT_E_EXPIRED,
	}
	for _, code := range invalid {
		if isErrno(err, code) {
			return Result{Status: StatusInvalid, Detail: err.Error()}
		}
	}
	if isErrno(err, windows.TRUST_E_NOSIGNATURE) {
		return Result{Status: StatusUnsigned}
	}
	return Result{Status: StatusUnknown, Detail: err.Error()}
}

func isErrno(err error, code windows.Handle) bool {
	var errno syscall.Errno
	return errors.As(err, &errno) && errno == syscall.Errno(code)
}

func upperHex(b []byte) string {
	const digits = "0123456789ABCDEF"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = digits[c>>4]
		out[i*2+1] = digits[c&0x0F]
	}
	return string(out)
}

// embeddedSigner devuelve el CN del certificado que firmó el archivo. Es
// informativo: ya sabemos que la firma verifica, esto solo dice de quién es.
// Cualquier fallo devuelve "" sin afectar el Status.
func embeddedSigner(path string) string {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}
	var encoding, contentType, formatType uint32
	var store, msg windows.Handle
	err = windows.CryptQueryObject(windows.CERT_QUERY_OBJECT_FILE, unsafe.Pointer(p),
		windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, windows.CERT_QUERY_FORMAT_FLAG_BINARY, 0,
		&encoding, &contentType, &formatType, &store, &msg, nil)
	if err != nil {
		return ""
	}
	defer windows.CertCloseStore(store, 0)
	defer procCryptMsgClose.Call(uintptr(msg))

	// CMSG_SIGNER_INFO: tamaño primero, contenido después.
	var size uint32
	procCryptMsgGetParam.Call(uintptr(msg), cmsgSignerInfoParam, 0, 0, uintptr(unsafe.Pointer(&size)))
	if size < 40 {
		return ""
	}
	buf := make([]byte, size)
	ret, _, _ := procCryptMsgGetParam.Call(uintptr(msg), cmsgSignerInfoParam, 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if ret == 0 {
		return ""
	}
	// Layout 64 bits: dwVersion(4)+pad(4); Issuer{cbData(4)+pad(4), pbData(8)}
	// en 8; SerialNumber{cbData, pbData} en 24.
	issuer := windows.CertNameBlob{
		Size: *(*uint32)(unsafe.Pointer(&buf[8])),
		Data: *(**byte)(unsafe.Pointer(&buf[16])),
	}
	serial := windows.CryptIntegerBlob{
		Size: *(*uint32)(unsafe.Pointer(&buf[24])),
		Data: *(**byte)(unsafe.Pointer(&buf[32])),
	}
	want := windows.CertInfo{Issuer: issuer, SerialNumber: serial}
	cert, err := windows.CertFindCertificateInStore(store,
		windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, 0,
		windows.CERT_FIND_SUBJECT_CERT, unsafe.Pointer(&want), nil)
	if err != nil || cert == nil {
		return ""
	}
	defer windows.CertFreeCertificateContext(cert)

	name := make([]uint16, 256)
	n := windows.CertGetNameString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, &name[0], uint32(len(name)))
	if n <= 1 {
		return ""
	}
	return windows.UTF16ToString(name[:n-1])
}

// hexOf existe para depuración de tests: hash legible.
func hexOf(b []byte) string { return hex.EncodeToString(b) }
