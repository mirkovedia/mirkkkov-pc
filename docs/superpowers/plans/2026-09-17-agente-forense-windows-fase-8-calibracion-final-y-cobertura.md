# Fase 8 — Calibración final, robustez y cobertura Implementation Plan

**Goal:** Llevar la máquina del desarrollador a `LIMPIO`, eliminar residuos y dependencias
frágiles, hacer el reporte verificable, cubrir emuladores/macros y publicar releases
reproducibles.

**Architecture:** Cambios aditivos sobre las fases anteriores. La lógica pura (`verdict`,
`fsforensic`) se corrige con tests hechos a partir de los nombres reales que fallaron. Las
capacidades nuevas de Windows (`authenticode`, `lockedfile`) viven en `winfs` y se testean con
fixtures sintéticos; los colectores las consumen y el motor solo ve JSON.

**Tech Stack:** Go 1.25+, `golang.org/x/sys/windows`, `go-webview2`. Sin CGO.

## Tareas

- [x] Task 1: Higiene — módulo, gofmt, tidy, LICENSE, versión por ldflags, CI con lint, release
- [x] Task 2: Calibración — cuatro falsos positivos + Timestamp (tests con nombres reales)
- [x] Task 3: Reporte — pubkey, collectors, build/installDate, status, `-verify`
- [x] Task 4: UI/runtime — reportPath, cancelación con limpieza VSS, quoting UAC
- [x] Task 5: `winfs/lockedfile` — lectura raw de hives; VSS como fallback; wmic → CIM
- [x] Task 6: `winfs/authenticode` — firma embebida y de catálogo; enriquecer servicios y tareas
- [x] Task 7: Colector `emulator` — emuladores, macros, herramientas de macro
- [x] Task 8: Colector `persistence` — Run/RunOnce, Startup, IFEO, AppInit
- [x] Task 9: Colector `processes` — procesos vivos con firma
- [x] Task 10: `sysconfig` + 4616 + journal recreado + lista KNOWN_CHEAT
- [x] Task 11: Interfaz — evidencia, filtros, cancelar, exportar, contexto
- [x] Task 12: README, consentimiento sincronizado, merge y push

## Resultado

Implementado en la rama `feat/fase-8-calibracion-final-y-cobertura`. 40 paquetes en verde, `go vet`
y `staticcheck` limpios.

Hallazgos de la propia implementación, no previstos en el diseño:

- Los manejadores JS `closeApp`/`cancelScan`/`exportHTML` pisaban los bindings de Go homónimos y se
  llamaban a sí mismos. El botón Cerrar estaba roto desde la Fase 6. Corregido con test de regresión.
- `[hidden]` perdía contra `display:flex`: el ecualizador de actividad se veía siempre.
- El binario `-H windowsgui` pisaba un stdout redirigido con `CONOUT$`; `-verify r.json > out.txt`
  dejaba el archivo vacío.
- `kernel32.dll` trae firma embebida en Windows 11 25H2; el camino de catálogo se ejercita con `cmd.exe`.

## Pendiente de validar en una máquina real

No se pudo correr un escaneo elevado desde la sesión de desarrollo. Falta confirmar sobre hardware
real, con doble clic y UAC:

1. Que la lectura raw de `SYSTEM`, `SOFTWARE` y `Amcache.hve` funciona (si no, cae a VSS y el campo
   `collectors` del reporte lo delata por la duración). `go test ./internal/winfs/lockedfile/` desde
   una consola elevada ejercita ese camino aislado.
2. Que el veredicto sobre la máquina del desarrollador es `LIMPIO`.
3. El mapeo del evento 4616 contra un `Security.evtx` real.
