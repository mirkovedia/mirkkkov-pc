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

- [ ] Task 1: Higiene — módulo, gofmt, tidy, LICENSE, versión por ldflags, CI con lint, release
- [ ] Task 2: Calibración — cuatro falsos positivos + Timestamp (tests con nombres reales)
- [ ] Task 3: Reporte — pubkey, collectors, build/installDate, status, `-verify`
- [ ] Task 4: UI/runtime — reportPath, cancelación con limpieza VSS, quoting UAC
- [ ] Task 5: `winfs/lockedfile` — lectura raw de hives; VSS como fallback; wmic → CIM
- [ ] Task 6: `winfs/authenticode` — firma embebida y de catálogo; enriquecer servicios y tareas
- [ ] Task 7: Colector `emulator` — emuladores, macros, herramientas de macro
- [ ] Task 8: Colector `persistence` — Run/RunOnce, Startup, IFEO, AppInit
- [ ] Task 9: Colector `processes` — procesos vivos con firma
- [ ] Task 10: `sysconfig` + 4616 + journal recreado + lista KNOWN_CHEAT
- [ ] Task 11: Interfaz — evidencia, filtros, cancelar, exportar, contexto
- [ ] Task 12: README, consentimiento sincronizado, merge y push
