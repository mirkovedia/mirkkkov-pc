# mirkkkov-pc

Agente forense por consentimiento para verificación anticheat en la comunidad de
Free Fire. Análisis forense post-hoc: reconstruye qué se ejecutó, qué se borró y
qué corre ahora en la máquina, con el jugador presente y previa aceptación
explícita.

Un solo `.exe`, sin instalador, sin CGO, sin puertos abiertos.

## Ejecución

**Doble clic en `mirkkkov.exe`.** Nada más.

El agente pide elevación por UAC solo, abre su propia ventana, muestra qué
revisa y qué no, y espera tu consentimiento explícito antes de tocar nada.
Durante el escaneo vas viendo el avance de cada fuente y podés cancelarlo; al
final, el veredicto con los hallazgos agrupados, filtrables y con su evidencia
desplegable.

El reporte queda como `reporte.json` junto al ejecutable. Desde la pantalla de
resultados se puede exportar además una copia `reporte.html` para mandarle a
alguien que no va a abrir un JSON.

### Modo consola

```
mirkkkov.exe -console                                    # reporte junto al .exe
mirkkkov.exe -console -out reporte.json -timeout 10m     # ruta explícita
mirkkkov.exe -console -server https://<servidor>          # contra un servidor
mirkkkov.exe -verify reporte.json                         # comprobar integridad
mirkkkov.exe -version
```

`Ctrl+C` cancela el escaneo de forma ordenada: el reporte parcial se escribe
igual, con estado `ABORTED`.

## Qué revisa

| Fuente | Qué aporta |
|---|---|
| Procesos en ejecución | Lo que corre ahora: ruta, hora de inicio y firma digital |
| Prefetch, BAM, ShimCache, AmCache | Qué programas se ejecutaron y cuándo, aunque ya no existan |
| USN Journal y MFT | Archivos creados, borrados y renombrados; timestomping; journal desactivado o recreado |
| Entradas borradas del MFT | Ejecutables eliminados que el sistema de archivos todavía recuerda |
| Servicios y drivers | Drivers de kernel de terceros, con verificación de firma |
| Tareas programadas | Tareas ocultas y desincronías entre disco y registro |
| Inicio automático | Run/RunOnce de máquina y de cada usuario, carpetas de inicio, IFEO, AppInit_DLLs, Winlogon |
| Emuladores y macros | BlueStacks, LDPlayer, MEmu, Nox, GameLoop y otros; sus archivos de macro; AutoHotkey y herramientas de automatización |
| Event Logs | Sesiones, borrado de logs, cambios de hora del sistema, manipulación binaria del `.evtx` |
| Configuración | Prefetch o Event Log deshabilitados, carpeta Prefetch vaciada |

Los hives del registro en uso se leen por acceso raw al volumen NTFS, sin crear
snapshots: el escaneo no deja nada que limpiar. VSS queda solo como respaldo.

## Veredicto

El motor no acusa por nombres feos ni por rutas raras. Cada tipo de artefacto
tiene una severidad base que se ajusta por su contenido:

- **Firma Authenticode.** Un driver, tarea, proceso o autorun con firma válida
  baja a informativo, esté donde esté. Un driver de kernel sin firma fuera de
  las rutas estándar sube a `HIGH`.
- **"No pude verificar" nunca es evidencia.** Un log ilegible, un archivo
  borrado o una API que falló no mueven el veredicto; un colector caído lo deja
  en `INCOMPLETO`, no en `LIMPIO`.
- **Combos.** Las señales anti-forenses de tipos distintos, la persistencia
  junto a un borrado de logs y un cambio de hora cerca de un timestomp escalan
  a `CRITICAL`.
- **Cheats conocidos.** Un `cheats.txt` junto al `.exe` (un SHA-1 por línea,
  seguido del nombre) se compara contra los hashes que AmCache guarda de cada
  ejecutable que corrió, incluso si ya fue borrado. El binario se distribuye
  sin hashes: la lista la mantiene quien opera el agente.

Niveles: `LIMPIO`, `INCOMPLETO`, `SOSPECHOSO`, `EVIDENCIA_FUERTE`.

## Integridad del reporte

Cada hallazgo entra en una cadena de hashes `H_n = SHA256(H_{n-1} ‖ SHA256(hallazgo))`
sembrada con el nonce de la sesión, y el último eslabón se firma con una clave
Ed25519 efímera. El reporte lleva el nonce y la clave pública, así que
cualquiera puede comprobarlo sin servidor:

```
mirkkkov.exe -verify reporte.json
```

Esto prueba que el archivo no fue editado después de generarse. **No** prueba
quién lo generó: eso solo lo da una sesión abierta contra un servidor que
registre la clave.

## Privacidad

El agente recolecta **solo metadatos forenses**: nombres, hashes, fechas, rutas
y firmas. Nunca contenido de archivos, credenciales, historial ni mensajes. De
los macros se cuentan los archivos y se anota su fecha; no se abre ninguno. No
se enumeran conexiones de red. Los identificadores de hardware se anonimizan
antes de salir del equipo.

## Build

```bash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath \
  -ldflags="-H windowsgui -X main.agentVersion=v0.2.0" -o mirkkkov.exe ./cmd/agent
```

El flag `-H windowsgui` evita que el doble clic abra una ventana de consola
detrás de la interfaz. El modo consola sigue funcionando: el agente se engancha
a la terminal desde la que se lo invocó y respeta la salida redirigida.

### Releases verificables

Un tag `vX.Y.Z` dispara `.github/workflows/release.yml`, que publica el `.exe`,
un `SHA256SUMS` y una atestación de procedencia firmada por GitHub:

```bash
gh attestation verify mirkkkov.exe --repo mirkovedia/mirkkkov-pc
```

### Desarrollo

```bash
go test ./...                                   # 40 paquetes; no requiere elevación
go vet ./... && staticcheck ./...
go run tools/previewui/main.go > preview.html   # ver la interfaz con un reporte simulado
```

Los tests que necesitan abrir el volumen en crudo se saltan solos fuera de una
consola elevada; corriendo `go test ./internal/winfs/lockedfile/` como
administrador se ejercita la lectura raw real.

## Licencia

MIT. Ver [LICENSE](LICENSE).
