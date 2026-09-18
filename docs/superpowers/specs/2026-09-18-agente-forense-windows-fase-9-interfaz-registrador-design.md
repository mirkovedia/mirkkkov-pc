# Agente Forense Windows — Fase 9: La interfaz como registrador (Design)

**Fecha:** 2026-09-18
**Estado:** Implementado
**Depende de:** Fase 6 (ventana WebView2), Fase 8 (fechas en los hallazgos, colectores nuevos)

## Contexto

La interfaz de las Fases 6 a 8 funcionaba, pero era una tarjeta oscura con un botón naranja: el
aspecto por defecto de cualquier herramienta "de seguridad". Nada en ella decía *instrumento
forense* y nada quedaba en la memoria. El pedido fue mejorarla mucho, no retocarla.

## La idea

**Mirkkkov reconstruye una línea de tiempo, así que la línea de tiempo es la protagonista.**

La interfaz es un *registrador de tira*, como un sismógrafo: un chasis gris hierro y una tira de
papel donde la actividad de la máquina queda dibujada en tinta. La tira es **un solo elemento que
recorre las tres pantallas**:

| Pantalla | Estado de la tira |
|---|---|
| Consentimiento | En blanco, con su cuadrícula y sus fechas. Dice qué se va a dibujar ahí. |
| Revisión en curso | Se dibuja fuente por fuente; una pluma ámbar recorre el papel. |
| Resultado | Completa y anotada: cada hallazgo con fecha es una marca que lleva a su fila. |

No es decoración. Contesta de un vistazo lo que más le importa a quien revisa: **cuándo** pasó
cada cosa. Una ráfaga de borrados media hora antes de la revisión, días enteros con la máquina
apagada o un registro casi vacío en una instalación vieja se ven sin leer una sola fila.

## El dato que la alimenta

`report.Activity`: un histograma por hora de los últimos 30 días, en tres canales.

| Canal | De dónde sale |
|---|---|
| `execution` | Prefetch (las ocho ejecuciones de cada programa), BAM, procesos vivos |
| `files` | USN journal, entradas borradas del MFT, timestomping |
| `session` | Inicios de sesión y reinicios, borrado de logs, cambios de hora |

Se calcula en `verdict.Activity` desde **todos** los artefactos con fecha, incluida la evidencia
neutra que el reporte solo resume. Son conteos por hora: no agrega ningún dato que no estuviera ya
cubierto por el consentimiento, y no entra en la cadena de custodia porque se deriva de los mismos
artefactos. Cada colector aporta su parte en el evento `collector_done`, que es lo que permite que
la tira se dibuje mientras la revisión corre; el reporte final trae la versión completa y reemplaza
lo acumulado en vivo.

## Sistema visual

**Paleta**

| Rol | Valor | Nota |
|---|---|---|
| Chasis | `#1e2327` | Gris hierro con un punto de verde. No negro: el negro con un acento brillante es el aspecto genérico del que se quería salir. |
| Papel | `#ece7d8` | Térmico. La tira, la evidencia desplegada y el fondo del HTML exportado. |
| Tinta azul / roja / verde | `#23466e` `#a5382a` `#2e6b50` | Ejecución, archivos, sesión. Sobre el chasis se usan aclaradas. |
| Lámpara | `#f0a23b` | El ámbar que ya era la marca: progreso, "ahora", acción principal. |
| Severidad | gris, azul, ámbar, naranja, rojo | Etiqueta de contorno; rellena solo la crítica. |

El riesgo asumido es el **papel claro dentro de un chasis oscuro**. Se justifica porque las marcas
densas de tinta oscura se leen mejor sobre claro que trazos luminosos sobre oscuro, y porque le da
un solo material a todo lo que es *registro*: la tira, la evidencia y el documento exportado.

**Tipografía.** Bahnschrift, la DIN de los paneles de instrumentos y la señalética, para
titulares y rótulos. Viene con Windows 10 y 11 y tiene eje de ancho variable, que se usa
condensado. Segoe UI Variable para leer y Cascadia Mono para los datos. **Ningún archivo de fuente
viaja en el `.exe`.**

**Movimiento.** Un solo momento orquestado: al mostrar el resultado, el papel se descubre de
izquierda a derecha. Durante la revisión, la pluma y la lámpara. Todo respeta
`prefers-reduced-motion`.

**Texto.** Todo se nombra por lo que la persona reconoce: "Diario de cambios de archivos" y no
`usn`, "Alto" y no `HIGH`. La acción se llama *revisión* en todo el recorrido. La oración bajo el
veredicto dice cuánto hay y qué hacer, en vez de repetir el titular. Los estados vacíos y de error
dicen qué pasó y cómo seguir.

## Decisiones de implementación

- **SVG y no canvas** para la tira: son unos cientos de nodos, y el HTML exportado se arma
  clonando el DOM, donde un canvas saldría vacío.
- **Los marcadores se crean con `createElementNS` y `textContent`**, nunca con cadenas: los
  títulos llevan nombres de archivo que controla quien es revisado.
- **La evidencia se construye al primer clic.** Con 400 hallazgos, 400 tablas castigarían la
  pantalla de resultados.
- **El HTML exportado sale en papel**: el mismo documento con las variables de color del chasis
  redefinidas, todo desplegado, sin scripts ni controles.
- **Ningún manejador JS global puede llamarse igual que un binding de Go.** Hay un test que lo
  impide: el botón Cerrar estuvo roto por eso desde la Fase 6.

## Revisión adversarial

El rediseño pasó por una revisión multiagente antes de publicarse: cuatro lentes en paralelo
(seguridad, lógica JS, CSS y accesibilidad, datos en Go) y, por cada lente, un verificador escéptico
cuyo trabajo era **refutar** cada hallazgo leyendo el código. 22 confirmados y 1 refutado; agrupados,
13 defectos. Los más serios no eran del rediseño: los destapó dibujar la actividad en el tiempo.

| Defecto | Desde | Consecuencia |
|---|---|---|
| BAM, ShimCache y AmCache nunca escalaban por nombre: su `Source` es el hive | Fase 4 | Un `aimbot.exe` ejecutado y borrado quedaba en las tres fuentes que sobreviven al borrado y el veredicto salía `LIMPIO` |
| El botón de carpeta podía ejecutar un archivo del revisado (`x.cmd\y`: el "padre" es un archivo) | Fase 6 | `explorer.exe <archivo>` lo abre con su asociación |
| El botón de carpeta aceptaba rutas UNC | Fase 6 | Autenticación SMB/NTLM desde el proceso elevado hacia un host elegido por el revisado |
| El timestomp se fechaba con `SI.Created`, el valor falsificado | Fase 3B-1 | El hallazgo anti-forense caía fuera del registro y del combo con el cambio de hora |
| `scan_done` podía perderse si alguien arrastraba la ventana | Fase 6 | La pantalla quedaba en "Revisando" con el reporte ya escrito |
| Ventana de 1100x780 fijos | Fase 6 | En 1366x768 o FHD al 150 % el botón Cancelar quedaba tras la barra de tareas |

Del rediseño mismo: la tapa del registro compartía la clase `.reveal` con el botón de carpeta y
medía 30x30, el HTML exportado omitía en silencio los hallazgos filtrados, las rutas largas
escondían el nombre del archivo, los caracteres bidi de un nombre hostil se obedecían en vez de
mostrarse, y el contraste del texto chico no llegaba a WCAG AA.

Cada arreglo tiene su test, y el escaneo real del CI confirmó `LIMPIO` con la escalada por nombre ya
activa sobre 474 entradas de ShimCache y 3996 de AmCache.

## Cómo verla sin compilar ni elevar

```bash
go run tools/previewui/main.go > preview.html
```

`preview.html`, `#scan`, `#results` y `#limpio` muestran cada pantalla con actividad simulada.
Los sufijos `,static`, `,open`, `,r48`, `,r168` y `,export` sirven para capturas: congelar
animaciones, desplegar evidencia, cambiar el rango y ver el documento exportado.

## Fuera de alcance

- Arrastrar sobre la tira para filtrar los hallazgos por rango de tiempo.
- Un cuarto carril de red: no está en el consentimiento.
- Tema claro para la ventana. El papel ya cubre el documento exportado, que es donde hacía falta.
