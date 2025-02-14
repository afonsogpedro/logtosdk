# Logto SDK para Go (Logto SDK for Go) - https://logto.io

## Descripción

El **Logto SDK para Go** es una biblioteca diseñada para interactuar con el servicio de autenticación y gestión de identidades [Logto](https://logto.io/). Esta biblioteca proporciona métodos para obtener tokens de acceso, gestionar aplicaciones y organizaciones, validar tokens JWS, y manejar solicitudes HTTP relacionadas con Logto.

El SDK está construido sobre las mejores prácticas de Go, utilizando estructuras de datos claras y funciones auxiliares para simplificar la interacción con la API de Logto. Además, incluye soporte para validación de tokens JWT, manejo de errores estandarizado y compatibilidad con frameworks populares como Gin.

---

## Índice

1. [Instalación](#instalación)
2. [Configuración](#configuración)
3. [Funcionalidades principales](#funcionalidades-principales)
    - [Obtención de tokens](#obtención-de-tokens)
    - [Gestión de aplicaciones y organizaciones](#gestión-de-aplicaciones-y-organizaciones)
    - [Validación de tokens JWS](#validación-de-tokens-jws)
4. [Manejo de errores](#manejo-de-errores)
5. [Ejemplos de uso](#ejemplos-de-uso)
6. [Contribuciones](#contribuciones)

---

## Instalación

Para utilizar este SDK, asegúrate de tener instalado Go en tu sistema. Luego, puedes instalar el paquete ejecutando:

```bash
  go get github.com/afonsogpedro/logtosdk
```

---

## Configuración

Antes de usar el SDK, necesitarás configurar un cliente con las credenciales de Logto. A continuación, se muestra cómo crear una instancia del cliente:

```go
import "github.com/tu-usuario/logtosdk"

func main() {
    client := logtosdk.NewLogtoClient(
        "https://your-logto-instance.com", // URL base de Logto
        nil,                               // Cliente HTTP personalizado (opcional)
        "your-client-id",                  // ID de tu aplicación
        "your-client-secret",              // Secreto de tu aplicación
        "your-resource",                   // Recurso a acceder de tu aplicación
        "your-client-resource",            // Recurso del cliente
        "your-client-scope",               // Alcance del cliente
    )
}
```
### Parámetros requeridos:

- host: La URL base de tu instancia de Logto.
- clientId: El ID de cliente proporcionado por Logto para tu aplicación.
- clientSecret: El secreto del cliente proporcionado por Logto para tu aplicación.
- resource : El recurso al que se solicitará acceso de tu aplicación.
- clientResource : El recurso asociado al cliente.
- clientScope : El alcance del cliente.

---

## Funcionalidades principales
### Obtención de tokens

El SDK permite obtener tokens de acceso utilizando el flujo de credenciales de cliente (client_credentials). Esto es útil para autenticar servicios backend sin intervención del usuario.

#### Ejemplo

```go
tokenResponse, err := client.GetTokenLogto()
if err != nil {
    fmt.Println("Error al obtener el token:", err)
    return
}
fmt.Println("Token de acceso:", tokenResponse.AccessToken)
```
También puedes manejar solicitudes HTTP directamente:

```go
http.HandleFunc("/logto/token", client.HandleTokenByClient)
```

### Gestión de aplicaciones y organizaciones
Puedes listar aplicaciones y organizaciones, así como obtener metadatos personalizados asociados a ellas.

#### Ejemplo: Obtener todas las aplicaciones

```go
apps, err := client.GetApplications("your-access-token")
if err != nil {
    fmt.Println("Error al obtener las aplicaciones:", err)
    return
}
for _, app := range apps {
    fmt.Printf("ID: %s, Nombre: %s\n", app.ID, app.Name)
}
```

#### Ejemplo: Obtener metadatos de una aplicación

```go
metadata, err := client.GetMetadata("your-access-token", "app-id")
if err != nil {
    fmt.Println("Error al obtener los metadatos:", err)
    return
}
fmt.Println("Datos personalizados de la aplicación:", metadata.App)
fmt.Println("Datos personalizados de la organización:", metadata.Org)
```

### Validación de tokens JWS
El SDK incluye una función para validar tokens JWS y extraer información útil, como el client_id.

#### Ejemplo

```go
clientID, err := client.GetClientIdByToken("your-jws-token")
if err != nil {
    fmt.Println("Error al validar el token:", err)
    return
}
fmt.Println("Client ID:", clientID)
```

---

## Manejo de errores
El SDK utiliza un sistema de manejo de errores estandarizado. Cada error incluye un código de estado HTTP y un mensaje descriptivo.

#### Ejemplo:

```go
response, err := client.GetApplications("invalid-token")
if err != nil {
    var httpErr *logtosdk.HTTPError
    if errors.As(err, &httpErr) {
        fmt.Printf("Código de error: %d, Mensaje: %s\n", httpErr.StatusCode, httpErr.Status)
    } else {
        fmt.Println("Error desconocido:", err)
    }
}
```

---

## Ejemplos de uso

 1. Obtener un token y listar aplicaciones

```go
package main

import (
    "fmt"
    "github.com/tu-usuario/logtosdk"
)

func main() {
    client := logtosdk.NewLogtoClient(
        "https://your-logto-instance.com",
        nil,
        "your-client-id",
        "your-client-secret",
        "your-resource",
        "your-client-resource",
        "your-client-scope",
    )

    // Obtener token
    tokenResp, err := client.GetTokenLogto()
    if err != nil {
        fmt.Println("Error al obtener el token:", err)
        return
    }

    // Listar aplicaciones
    apps, err := client.GetApplications(tokenResp.AccessToken)
    if err != nil {
        fmt.Println("Error al obtener las aplicaciones:", err)
        return
    }

    for _, app := range apps {
        fmt.Printf("ID: %s, Nombre: %s\n", app.ID, app.Name)
    }
}
```

 2. Validar un token JWS

```go
package main

import (
    "fmt"
    "github.com/tu-usuario/logtosdk"
)

func main() {
    client := logtosdk.NewLogtoClient(
        "https://your-logto-instance.com",
        nil,
        "your-client-id",
        "your-client-secret",
        "your-resource",
        "your-client-resource",
        "your-client-scope",
    )

    token := "your-jws-token"
    clientID, err := client.GetClientIdByToken(token)
    if err != nil {
        fmt.Println("Error al validar el token:", err)
        return
    }
    fmt.Println("Client ID:", clientID)
}
```

---

## Contribuciones
Si deseas contribuir al desarrollo de este SDK, sigue estos pasos:

1. Haz un fork del repositorio.
2. Crea una rama para tu nueva funcionalidad o corrección (git checkout -b feature/nueva-funcionalidad).
3. Realiza tus cambios y haz commit (git commit -m "Añadir nueva funcionalidad").
4. Sube tus cambios (git push origin feature/nueva-funcionalidad).
5. Abre un pull request describiendo tus cambios.