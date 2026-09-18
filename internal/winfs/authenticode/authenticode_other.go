//go:build !windows

package authenticode

// verifyFile no está disponible fuera de Windows: todo es unknown, que el
// motor de severidad nunca interpreta como evidencia.
func verifyFile(path string) Result {
	return Result{Status: StatusUnknown, Detail: "verificación de firma solo disponible en Windows"}
}
