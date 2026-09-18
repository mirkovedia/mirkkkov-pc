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

## Validación con escaneos reales (2026-09-18)

La sesión de desarrollo corre sin elevación, pero el runner de GitHub Actions corre elevado. El CI
ahora compila el binario, acepta el consentimiento por stdin, escanea la máquina del runner,
verifica la cadena de custodia del reporte y resume cada colector. Tres corridas, cada una con su
lección:

| Corrida | Veredicto | Qué destapó |
|---|---|---|
| 1 | `SOSPECHOSO` | `FSCTL_GET_NTFS_FILE_RECORD` entrega el registro con el fixup ya aplicado y el parser exigía la forma de disco: la lectura raw fallaba siempre y, de paso, el colector de timestomping nunca había evaluado un archivo desde la Fase 3B-1. Dos falsos positivos: `System.Runtime.Loader.dll` y `rust-analyzer-proc-macro-srv.exe`. `deleted_entries` caía con "The parameter is incorrect": buffers sin alinear en lecturas crudas. |
| 2 | `INCOMPLETO` | Con el campo `diagnostics` nuevo: `SOFTWARE` reparte su `$DATA` en una lista de atributos; el respaldo VSS por PowerShell pasaba `Volume` vacío; y el staging todo-o-nada tiraba un `SYSTEM` ya copiado. |
| 3 | **`LIMPIO`** | 14 de 14 colectores sin fallos, los tres hives por acceso raw NTFS, reporte verificado, unos 14 segundos de escaneo. |

Calibración aparte sobre la máquina del desarrollador con los colectores que no requieren elevación
(`processes`, `emulator`): de `SOSPECHOSO` a `LIMPIO` tras tratar las apps MSIX como firmadas a
nivel de paquete y bajar a LOW el proceso sin firma dentro del perfil.

## Pendiente

1. Escaneo completo con doble clic y UAC sobre la máquina del desarrollador, que tiene software que
   el runner no tiene (drivers de anticheat de terceros, tareas de Google y MSI). Los tests
   reproducen esos casos con sus nombres reales, pero falta la corrida.
2. El mapeo del evento 4616 contra un `Security.evtx` con cambios de hora reales.
3. Publicar el primer release: `git tag -a v0.2.0 -m "v0.2.0" && git push origin v0.2.0` dispara
   `release.yml`. Es una publicación pública, así que queda a decisión del mantenedor.
