# Agente Forense Windows — Fase 8: Calibración final, robustez y cobertura (Design)

**Fecha:** 2026-09-17
**Estado:** Aprobado por el usuario ("lo dejo en tus manos, implementa todo lo mejorable")
**Depende de:** Fases 1–7

## Contexto

El reporte real del 2026-08-05 (438 hallazgos) sigue dando `EVIDENCIA_FUERTE` sobre la máquina
del desarrollador. La causa no son once colectores ruidosos sino cuatro fallas de calibración
concretas más un combo alimentado por ellas:

| Falso positivo | Hallazgos | Causa |
|---|---|---|
| Drivers en `\SystemRoot\System32\DriverStore\` en MEDIUM | 56 | `serviceDriverRule` compara la ruta cruda; la normalización de `\SystemRoot\` vive en `winfs/services` y no se reutiliza |
| `.js.gz` de Teams con tokens `esp`/`loader` en MEDIUM | 174 | los marcadores débiles escalan sobre cualquier extensión |
| `service_no_install_log` en MEDIUM | 56 | los logs rotan; un driver viejo nunca tiene su 7045 |
| `PostponeDeviceSetupToast_<SID>_0` hive_only → CRITICAL | 1 | tarea propia de Windows en la raíz del árbol, fuera de `Microsoft\` |

Además se detectaron defectos de robustez: `Finding.Timestamp` nunca se asigna, la GUI espera un
campo `reportPath` que no existe, cerrar la ventana a mitad del escaneo deja shadow copies
huérfanas, VSS depende de `wmic` (removido en Windows 11 24H2+), el reporte local no incluye la
clave pública (firma inverificable), la relanzada UAC no cita argumentos con espacios y
`Machine.Build` va siempre vacío.

## Objetivo

1. Que la máquina del desarrollador dé `LIMPIO`.
2. Que el agente no deje residuos ni dependa de herramientas removidas.
3. Que el reporte sea verificable por un tercero sin servidor.
4. Que el producto cubra lo que el consentimiento promete: emuladores y macros.
5. Release reproducible y verificable desde GitHub.

## Decisiones

### Calibración (`verdict`)

- `serviceDriverRule` normaliza el `ImagePath` con `services.NormalizeImagePath` (exportada) y
  considera normales `\windows\system32\` y `\windows\syswow64\` completos, no solo `drivers\`.
- Los marcadores **débiles** de `fsforensic` solo cuentan sobre nombres con extensión forense
  (`.exe`, `.dll`, `.sys`, scripts). Los fuertes siguen contando sobre cualquier nombre.
- `service_no_install_log` baja a INFO, igual que `task_no_register_log`.
- `scheduled_task_desync` hive_only baja a INFO cuando el nombre termina en un SID
  (`…-S-1-5-21-…-1001` o `_0`) o está en una allowlist corta de tareas raíz de Windows.
- `Finding.Timestamp` se rellena desde `timeOf`.

### Firma Authenticode (`winfs/authenticode`)

`WinVerifyTrustEx` de `x/sys/windows` (embebida) más las funciones `CryptCATAdmin*` de
`wintrust.dll` vía `LazyDLL` (catálogo). Cero CGO. Devuelve `Status` (`signed`, `unsigned`,
`invalid`, `unknown`) y `Signer`. Los colectores de servicios, tareas y procesos enriquecen sus
artefactos con la firma; el motor la usa: firmado válido → INFO; driver kernel sin firma fuera de
rutas estándar → HIGH.

### Lectura de archivos bloqueados (`winfs/lockedfile`)

Los hives en uso se leen por acceso raw NTFS con la maquinaria existente: handle con acceso 0 →
`GetFileInformationByHandle` (nº de registro MFT) → `FSCTL_GET_NTFS_FILE_RECORD` → data runs →
lectura por offset del volumen. VSS queda como **fallback**, y dentro de VSS `wmic` cae a
PowerShell CIM si no está. Sin snapshot no hay residuo que limpiar.

### Cancelación

`ui.Run` recibe un contexto que se cancela al cerrar la ventana o al pulsar "Cancelar". El
escaneo respeta el contexto y el `defer` de VSS corre antes de salir.

### Reporte

Campos nuevos: `pubkey`, `collectors[]` (nombre, artefactos, duración, error), `machine.build`,
`machine.installDate`. `status` pasa a `ABORTED` si el contexto se agotó. Modo `-verify
reporte.json` recomputa la cadena y valida la firma.

### Colectores nuevos

| Colector | Tipo de artefacto | Regla base |
|---|---|---|
| `emulator` | `emulator.installed`, `emulator.macro`, `macro_tool` | INFO / MEDIUM / LOW, categoría EMULATOR |
| `persistence` | `autorun`, `ifeo_debugger`, `appinit_dll`, `startup_entry` | INFO (neutro) / MEDIUM / HIGH / INFO |
| `processes` | `process` | neutro; escala por nombre y por falta de firma |
| `sysconfig` | `config.prefetch_disabled`, `config.eventlog_disabled`, `usn.journal_recreated` | MEDIUM / HIGH / HIGH, ANTI_FORENSIC |
| `eventlog` | `eventlog.time_changed` (4616) | MEDIUM, ANTI_FORENSIC |
| `verdict` | `amcache` con SHA-1 en lista embebida → KNOWN_CHEAT | CRITICAL |

### Interfaz

Evidencia expandible, filtros por severidad y texto, botón cancelar, ruta del reporte visible,
exportación HTML autocontenida, contexto de máquina (build, instalación, uptime), badge de firma.

### Release e higiene

Módulo renombrado a `github.com/mirkovedia/mirkkkov-pc`. `LICENSE` MIT. CI con gofmt, vet,
staticcheck y govulncheck. Workflow de release por tag `v*` con `SHA256SUMS` y atestación de
procedencia. Versión inyectada por `-ldflags -X`.

## Fuera de alcance

- Servidor de verificación remoto.
- Conexiones de red de procesos (no está en el consentimiento).
- Firma Authenticode del propio `.exe` (requiere certificado pago).
