# ethlambda

<!-- hy-mt2-i18n:start -->
[English](./README.md) | [中文](./README_zh-CN.md) | [日本語](./README_ja.md) | **Español**
<!-- hy-mt2-i18n:end -->


Implementación minimalista, rápida y modular del cliente Lean Ethereum, escrita en Rust.

🌐 Visite nuestro sitio web en [**ethlambda.xyz**](https://ethlambda.xyz) para conocer más sobre el proyecto.

## Primeros pasos

### Requisitos previos

- [Rust](https://rust-lang.org/tools/install)
- [Git](https://git-scm.com/install)
- [Docker](https://www.docker.com/get-started)
- [yq](https://github.com/mikefarah/yq#install)

### Compilación y pruebas

Utilizamos `cargo` como nuestro sistema de construcción, pero preferimos `make` como una capa de abstracción práctica para tareas comunes. Estos son algunos de los objetivos habituales:

```sh
# Formatea todo el código
make fmt
# Verifica y analiza el código en busca de errores
make lint
# Ejecuta todas las pruebas
make test
# Crea una imagen Docker etiquetada como "ghcr.io/lambdaclass/ethlambda:local"
make docker-build DOCKER_TAG=local
```

Ejecute `make help` o consulte nuestro [`Makefile`](./Makefile) para conocer otros comandos útiles.

### Ejecución en un devnet

Para ejecutar un devnet local con varios clientes utilizando [lean-quickstart](https://github.com/blockblaz/lean-quickstart):

```sh
# Esto clonará lean-quickstart, generará la imagen Docker y iniciará un devnet local
make run-devnet
```

Esto genera archivos de inicio nuevos y activa las métricas en todos los clientes configurados. Presione `Ctrl+C` para detener todos los nodos.

> **Nota:** En Linux, el rendimiento de QUIC se beneficia de buffers de recepción UDP más grandes. Si ve advertencias relacionadas con el tamaño de los buffers, aumente el límite del kernel:
> ```sh
> sudo sysctl -w net.core.rmem_max=7340032
> sudo sysctl -w net.core.wmem_max=7340032
> ```
> Para que estos cambios se mantengan tras reiniciar el sistema, agréguelos a `/etc/sysctl.conf`. En el caso de Docker, utilice la opción `--sysctl net.core.rmem_max=7340032 --sysctl net.core.wmem_max=7340032`.

> **Importante:** Al ejecutar los nodos manualmente (fuera de `make run-devnet`), al menos un nodo debe iniciarse con `--is-aggregator` para que las certificaciones se agrupen e incluyan en los bloques. Sin esta opción, la red generará bloques pero nunca los finalizará.

Para configuraciones personalizadas de devnet, vaya a `lean-quickstart/local-devnet/genesis/validator-config.yaml` y edite el archivo antes de ejecutar la orden anterior. Consulte la documentación de `lean-quickstart` para obtener más detalles sobre cómo configurar devnet.

## Contribuir

¡Aceptamos contribuciones! Por favor, lea nuestro [CONTRIBUTING.md](./CONTRIBUTING.md) para conocer las pautas sobre cómo participar.

## Comunidad

- **Telegram**: [ethlambda group](https://t.me/ethlambda_client), donde publicamos actualizaciones diarias; pásate por allí para hacer preguntas o charlar sobre cualquier tema relacionado con Lean.  
- **X (Twitter)**: [@ethlambda_lean](https://twitter.com/ethlambda_lean) para actualizaciones ocasionales.  
- **Llamada semanal de la comunidad**: todos los viernes, en transmisión en vivo en [@class_lambda](https://x.com/class_lambda); el enlace de la llamada se publica previamente en Telegram.  
- **Coordinación del ecosistema**: las [llamadas PQ Interop](https://github.com/ethereum/pm/issues?q=is%3Aissue+%22PQ+Interop%22+in%3Atitle) en `ethereum/pm` tratan sobre el trabajo conjunto entre clientes en Lean Ethereum y las actualizaciones relacionadas; los enlaces de las reuniones se publican en cada incidencia.

## Filosofía

Muchos clientes establecidos desde hace tiempo van acumulando sobrecarga con el paso del tiempo. Esto suele ocurrir debido a la necesidad de dar soporte a funciones obsoletas para los usuarios existentes o por intentos de implementar software excesivamente ambicioso. El resultado son sistemas a menudo complejos, difíciles de mantener y propensos a errores.

Por el contrario, nuestra filosofía se basa en la simplicidad. Nos esforzamos por escribir el mínimo código posible, dar prioridad a la claridad y adoptar un diseño sencillo. Creemos que este enfoque es la mejor forma de crear un cliente que sea rápido y resistente. Al seguir estos principios, podremos iterar rápidamente e explorar funciones de próxima generación desde temprano.

Lea más sobre nuestra filosofía de ingeniería [en esta entrada de nuestro blog](https://blog.lambdaclass.com/lambdas-engineering-philosophy/).

## Principios de diseño

- Garantizar una configuración y ejecución sin esfuerzo en todos los entornos de destino.  
- Ser verticalmente integrado, con la menor cantidad posible de dependencias.  
- Estar estructurado de manera que sea fácil extenderlo.  
- Contar con un sistema de tipos sencillo; evitar que los genericos se propaguen por todo el código.  
- Utilizar pocas abstracciones; no generalizar salvo cuando sea absolutamente necesario. Repetir código dos o tres veces está bien.  
- Dar prioridad a la legibilidad y mantenibilidad del código sobre optimizaciones prematuras.  
- Evitar la concurrencia dispersa por todo el código; la concurrencia añade complejidad. Úsela solo cuando sea estrictamente necesario.

## 📚 Referencias y agradecimientos

Los siguientes enlaces, repositorios, empresas y proyectos han sido fundamentales para el desarrollo de este repositorio; hemos aprendido mucho de ellos y queremos agradecerles y darles nuestro reconocimiento.

- [Ethereum](https://ethereum.org/en/)  
- [LeanEthereum](https://github.com/leanEthereum)  
- [Zeam](https://github.com/blockblaz/zeam)  
- [Lantern](https://github.com/Pier-Two/lantern)

Si olvidamos incluir a alguien, por favor abre un ticket para que podamos agregarlo. Siempre nos esforzamos por citar las fuentes de inspiración y el código que utilizamos, pero al ser una organización formada por varias personas, pueden ocurrir errores y alguien podría olvidarse de incluir una referencia.

## Estado actual

El cliente implementa las funcionalidades principales de un cliente de consenso Lean Ethereum:

- **Redes** — conexiones entre pares mediante libp2p, manejo de mensajes STATUS, gossipsub para bloques y certificaciones  
- **Gestión de estado** — generación del estado inicial, función de transición de estado, procesamiento de bloques  
- **Elección de bifurcación** — implementación de la regla de elección de bifurcación 3SF-mini con selección del líder basada en certificaciones  
- **Deberes de los validadores** — generación y difusión de certificaciones, construcción de bloques

Funciones adicionales:

- Soporte para [leanMetrics](docs/metrics.md) con el fin de realizar monitoreo y garantizar la observabilidad.  
- Integración con [lean-quickstart](https://github.com/blockblaz/lean-quickstart) para facilitar la ejecución en entornos de desarrollo.

### Versiones del contenedor

Las imágenes Docker se publican en `ghcr.io/lambdaclass/ethlambda` con las siguientes etiquetas:

| Tag | Descripción |
|-----|-------------|
| `devnetX` | Imagen estable para un devnet específico (p. ej., `devnet4`) |
| `latest` | Alias de la imagen estable más reciente del devnet en ejecución actualmente |
| `unstable` | Compilada a partir del último commit principal; se promueve a `devnetX`/`latest` una vez probada |
| `sha-XXXXXXX` | Commit específico |

El archivo [`RELEASE.md`](./RELEASE.md) contiene más detalles sobre nuestro proceso de lanzamiento y cómo etiquetar nuevas imágenes.

### pq-devnet-5

Actualmente estamos utilizando la especificación `pq-devnet-5`. Existe una etiqueta de Docker `devnet5` disponible para esta versión.

### pq-devnet-6

`pq-devnet-6` se encuentra en fase de planificación; aún no se han especificado funcionalidades. Las opciones más probables son reemplazar [LMD-GHOST](docs/lmd_ghost.md) y [3SF-mini](docs/3sf_mini.md), o realizar la [integración con la capa de ejecución](https://github.com/lambdaclass/ethlambda/pull/367).

### Versiones anteriores de devnet

Se publican etiquetas Docker para cada devnet, con el formato `devnetX` (es decir, `devnet1`, `devnet2`, `devnet3`, `devnet4`).

Se deja de ofrecer soporte para las versiones anteriores de los devnets cuando se lanza la versión siguiente.

## Funciones futuras / Hoja de ruta

Escribimos una [entrada de blog](https://blog.lambdaclass.com/ethlambda-devnet-5-and-beyond/) sobre qué creemos que debería incluirse en el futuro cercano.

Algunas de las funcionalidades que pretendemos implementar en un futuro cercano, por orden de prioridad:

- [Optimizar la construcción de bloques](https://github.com/lambdaclass/ethlambda/issues/465)
- [Utilizar diferencias de estado para almacenarlos en la base de datos](https://github.com/lambdaclass/ethlambda/issues/238)
- [Prototipar Goldfish + RLMD GHOST + BFT — devnet-6](https://github.com/lambdaclass/ethlambda/pull/434)
- [Integrarse con clientes de ejecución](https://github.com/lambdaclass/ethlambda/pull/367), en particular [ethrex](https://github.com/lambdaclass/ethrex) — devnet-7
- Sustituir libp2p por el experimental [ethp2p](https://github.com/ethp2p/ethp2p), que estamos portando a Rust
- [Añadir un programa invitado y prueba ZK del STF](https://github.com/lambdaclass/ethlambda/issues/156)
- Reescribir el STF en un lenguaje de programación concreto para permitir su verificación formal

### Funcionalidades experimentales

Contamos con una formalización de tipo prueba de concepto de una parte de la función de transición de estado en Lean4, disponible en la PR [#269](https://github.com/lambdaclass/ethlambda/pull/269).
