package logtosdk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// HTTPError es un error personalizado que incluye el código de estado HTTP.
type HTTPError struct {
	StatusCode int
	Status     string
	Message    string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("Error en la solicitud: %s", e.Message)
}

type Client struct {
	host           string
	httpClient     *http.Client
	ClientId       string
	ClientSecret   string
	Resource       string
	ClientResource string
	ClientScope    string
}

type Application struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	CustomData  map[string]interface{} `json:"customData"`
}

type Organization struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	CustomData  map[string]interface{} `json:"customData"`
}

// StandardResponse define el formato estándar para todas las respuestas.
type StandardResponse struct {
	Status string      `json:"status"` // "error" o "success"
	Code   int         `json:"code"`   // Código HTTP (por ejemplo, 200, 404, etc.)
	Data   interface{} `json:"data"`   // Datos en caso de éxito o información del error
}

// ErrorData contiene la información detallada de un error.
type ErrorData struct {
	Code    string `json:"code"`    // Por ejemplo, "RECURSO_NO_ENCONTRADO"
	Message string `json:"message"` // Mensaje de error
	Time    string `json:"time"`    // Timestamp en formato RFC3339
	Route   string `json:"route"`   // Ruta del endpoint
}

type DecodedJWT struct {
	Header  map[string]interface{} `json:"header"`
	Payload map[string]interface{} `json:"payload"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IdToken      string `json:"id_token,omitempty"`
}

type Metadata struct {
	App map[string]interface{} `json:"app"`
	Org map[string]interface{} `json:"org"`
}

// JWK representa una clave JSON Web Key.
type JWK struct {
	Kty string `json:"kty"` // Tipo de clave, e.g., "RSA" o "EC"
	Kid string `json:"kid"` // Identificador de la clave
	Use string `json:"use"` // Uso de la clave, ej. "sig"
	Alg string `json:"alg"` // Algoritmo, ej. "ES384" o "RS256"
	// Campos para RSA
	N string `json:"n,omitempty"` // Módulo
	E string `json:"e,omitempty"` // Exponente
	// Campos para EC
	Crv string `json:"crv,omitempty"` // Curva, ej. "P-384"
	X   string `json:"x,omitempty"`   // Coordenada X
	Y   string `json:"y,omitempty"`   // Coordenada Y
}

// JWKS representa un conjunto de JWKs.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// Response es la estructura de la respuesta que retorna ValidateLogtoJWS.
type Response struct {
	Status string                 `json:"status"`
	Data   map[string]interface{} `json:"data"`
}

type LogtoError struct {
	Code             string `json:"code"`
	Message          string `json:"message"`
	ErrorField       string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

const (
	BearerPrefix                 = "Bearer "
	ErrCreatingRequest           = "error al crear la solicitud: %w"
	ErrPerformingRequest         = "error al realizar la solicitud: %w"
	ErrReadingResponse           = "error al leer la respuesta: %w"
	ErrRequestFailed             = "error en la solicitud: código %d, respuesta: %s"
	ErrEmptyResponse             = "la respuesta está vacía"
	ErrDeserializingJSONResponse = "error al deserializar la respuesta JSON: %w"
	XForwardedForHeader          = "X-Forwarded-For"
	ContentTypeHeader            = "Content-Type"
	MethodNotAllowed             = "Método no permitido"
	TokenNotProvided             = "Token no proporcionado"
	InvalidTokenFormat           = "Formato de token inválido"
	ApplicationJSON              = "application/json"
	ApplicationForm              = "application/x-www-form-urlencoded"
)

// NewLogtoClient es el constructor del cliente, que se encarga de configurar el servidor de Logto y el cliente HTTP
// para realizar las solicitudes. Si httpClient es nil, se utiliza http.DefaultClient. Se deben usar el los datos de
// configuración de Logto de maquina a maquina con permisos al servidor default de Logto.
func NewLogtoClient(host string, httpClient *http.Client, cliendId, clientSecret, resource, clientResource, clientScope string) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{
		host:           host,
		httpClient:     httpClient,
		ClientId:       cliendId,
		ClientSecret:   clientSecret,
		Resource:       resource,
		ClientResource: clientResource,
		ClientScope:    clientScope,
	}
}

// Métodos de la API

// GetApplications obtiene la información de todas las aplicaciones.
// Retorna un slice de Application.
func (c *Client) GetApplications(token string) ([]Application, error) {
	req, err := http.NewRequest("GET", c.host+"/api/applications", nil)
	if err != nil {
		return nil, fmt.Errorf(ErrCreatingRequest, err)
	}
	req.Header.Set("Authorization", BearerPrefix+token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf(ErrPerformingRequest, err)
	}
	defer closeResponseBody(resp)
	return parseResponse[[]Application](resp)
}

// GetMetaApplications obtiene la información de una aplicación.
// Retorna un Application.
func (c *Client) GetMetaApplications(token string, applicationID string) (*Application, error) {
	requestURL := fmt.Sprintf("%s/api/applications/%s", c.host, applicationID)
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf(ErrCreatingRequest, err)
	}
	req.Header.Set("Authorization", BearerPrefix+token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf(ErrPerformingRequest, err)
	}
	defer closeResponseBody(resp)

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf(ErrReadingResponse, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(ErrRequestFailed, resp.StatusCode, string(bodyBytes))
	}

	if len(bodyBytes) == 0 {
		return nil, fmt.Errorf(ErrEmptyResponse)
	}

	var app Application
	if err := json.Unmarshal(bodyBytes, &app); err != nil {
		return nil, fmt.Errorf(ErrDeserializingJSONResponse, err)
	}
	return &app, nil
}

// GetOrganizations obtiene todas las organizaciones.
// Retorna una lista de Organization.
func (c *Client) GetOrganizations(token string) ([]Organization, error) {
	req, err := http.NewRequest("GET", c.host+"/api/organizations", nil)
	if err != nil {
		return nil, fmt.Errorf(ErrCreatingRequest, err)
	}
	req.Header.Set("Authorization", BearerPrefix+token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf(ErrPerformingRequest, err)
	}
	defer closeResponseBody(resp)
	return parseResponse[[]Organization](resp)
}

// GetOrganizationsApplication obtiene las organizaciones asociadas a una aplicación.
// Retorna una lista de Organization.
func (c *Client) GetOrganizationsApplication(token string, applicationID string) ([]Organization, error) {
	// Construir la URL correctamente
	requestURL := fmt.Sprintf("%s/api/organizations/%s/applications", c.host, applicationID)

	// Crear la solicitud HTTP GET
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf(ErrCreatingRequest, err)
	}
	req.Header.Set("Authorization", BearerPrefix+token)

	// Realizar la solicitud HTTP
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf(ErrPerformingRequest, err)
	}
	defer closeResponseBody(resp)

	// Leer el cuerpo de la respuesta
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf(ErrReadingResponse, err)
	}

	// Verificar el código de estado
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(ErrRequestFailed, resp.StatusCode, string(bodyBytes))
	}

	// Verificar si la respuesta está vacía
	if len(bodyBytes) == 0 {
		return nil, fmt.Errorf(ErrEmptyResponse)
	}

	// Deserializar la respuesta en una lista de organizaciones
	var orgs []Organization
	if err := json.Unmarshal(bodyBytes, &orgs); err != nil {
		return nil, fmt.Errorf(ErrDeserializingJSONResponse, err)
	}

	return orgs, nil
}

// GetApplicationOrganizations obtiene las aplicaciones asociadas a una organización.
// Retorna una lista de Aplicaciones.
func (c *Client) GetApplicationOrganizations(token string, applicationID string) ([]Application, error) {
	// Construir la URL correctamente
	requestURL := fmt.Sprintf("%s/api/applications/%s/organizations", c.host, applicationID)

	// Crear la solicitud HTTP GET
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf(ErrCreatingRequest, err)
	}
	req.Header.Set("Authorization", BearerPrefix+token)

	// Realizar la solicitud HTTP
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf(ErrPerformingRequest, err)
	}
	defer closeResponseBody(resp)

	// Leer el cuerpo de la respuesta
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf(ErrReadingResponse, err)
	}

	// Verificar el código de estado
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(ErrRequestFailed, resp.StatusCode, string(bodyBytes))
	}

	// Verificar si la respuesta está vacía
	if len(bodyBytes) == 0 {
		return nil, fmt.Errorf(ErrEmptyResponse)
	}

	// Deserializar la respuesta en una lista de organizaciones
	var apps []Application
	if err := json.Unmarshal(bodyBytes, &apps); err != nil {
		return nil, fmt.Errorf(ErrDeserializingJSONResponse, err)
	}

	return apps, nil
}

// GetMetaOrganizations obtiene las organizaciones asociadas a un cliente.
// Retorna una lista de Organization.
func (c *Client) GetMetaOrganizations(token string, applicationID string) ([]Organization, error) {
	// Construir la URL correctamente
	requestURL := fmt.Sprintf("%s/api/applications/%s/organizations", c.host, applicationID)

	// Crear la solicitud HTTP GET
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf(ErrCreatingRequest, err)
	}
	req.Header.Set("Authorization", BearerPrefix+token)

	// Realizar la solicitud HTTP
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf(ErrPerformingRequest, err)
	}
	defer closeResponseBody(resp)

	// Leer el cuerpo de la respuesta
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf(ErrReadingResponse, err)
	}

	// Verificar el código de estado
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(ErrRequestFailed, resp.StatusCode, string(bodyBytes))
	}

	// Verificar si la respuesta está vacía
	if len(bodyBytes) == 0 {
		return nil, fmt.Errorf(ErrEmptyResponse)
	}

	// Deserializar la respuesta en una lista de organizaciones
	var orgs []Organization
	if err := json.Unmarshal(bodyBytes, &orgs); err != nil {
		return nil, fmt.Errorf(ErrDeserializingJSONResponse, err)
	}

	return orgs, nil
}

// GetTokenByClient obtiene un token de Logto utilizando las credenciales del cliente.
func (c *Client) GetTokenByClient(form url.Values, headers http.Header, clientIP, resource, scope string) (*TokenResponse, error) {
    urlStr := c.host + "/oidc/token"
    form.Set("resource", resource)
    form.Set("grant_type", "client_credentials")
    form.Set("scope", scope)

    req, err := http.NewRequest("POST", urlStr, strings.NewReader(form.Encode()))
    if err != nil {
        return nil, fmt.Errorf(ErrCreatingRequest, err)
    }

    // Copiamos los encabezados de la solicitud original.
    for key, values := range headers {
        for _, value := range values {
            req.Header.Add(key, value)
        }
    }

    // Agregamos o actualizamos el encabezado X-Forwarded-For con la IP del cliente original.
    if clientIP != "" {
        existingForwardedFor := req.Header.Get(XForwardedForHeader)
        if existingForwardedFor != "" {
            clientIP = clientIP + ", " + existingForwardedFor
        }
        req.Header.Set(XForwardedForHeader, clientIP)
    }

    // Aseguramos que el Content-Type sea correcto.
    req.Header.Set(ContentTypeHeader, ApplicationForm)

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf(ErrPerformingRequest, err)
    }
    defer closeResponseBody(resp)

    bodyBytes, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("error reading response body: %w", err)
    }

    // Detectar compresión y descomprimir si es necesario
    var reader io.Reader
    switch resp.Header.Get("Content-Encoding") {
    case "gzip":
        gzipReader, err := gzip.NewReader(bytes.NewReader(bodyBytes))
        if err != nil {
            return nil, fmt.Errorf("error creando lector gzip: %w", err)
        }
        defer gzipReader.Close()
        reader = gzipReader
    default:
        reader = bytes.NewReader(bodyBytes)
    }

    uncompressedBody, err := io.ReadAll(reader)
    if err != nil {
        return nil, fmt.Errorf("error descomprimiendo cuerpo: %w", err)
    }

    // Manejo de errores en la respuesta
    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        var logtoErr LogtoError
        if err := json.Unmarshal(uncompressedBody, &logtoErr); err != nil {
            return nil, fmt.Errorf("error decoding Logto error response: %w", err)
        }

        errES := logtoErr.ErrorDescription
        switch errES {
        case "client authentication failed":
            errES = "autenticación del cliente falló"
        case "no client authentication mechanism provided":
            errES = "no se proporcionó un mecanismo de autenticación del cliente"
        default:
            errES = logtoErr.ErrorDescription
        }

        if strings.HasPrefix(errES, "invalid client") {
            errES = strings.Replace(errES, "invalid client", "cliente inválido", 1)
        }

        // Retornar HTTPError con el código de estado real y la descripción del error
        return nil, &HTTPError{
            StatusCode: resp.StatusCode,
            Status:     logtoErr.Code,
            Message:    errES,
        }
    }

    // Procesar respuesta exitosa
    var tokenResp TokenResponse
    if err := json.Unmarshal(uncompressedBody, &tokenResp); err != nil {
        return nil, fmt.Errorf("error decodificando respuesta de token: %w", err)
    }

    return &tokenResp, nil
}

// GetTokenLogto obtiene un token de Logto utilizando las credenciales del cliente.
func (c *Client) GetTokenLogto() (*TokenResponse, error) {
	// Validar que los campos necesarios estén configurados en el cliente
	if c.ClientId == "" || c.ClientSecret == "" || c.Resource == "" || c.host == "" {
		return nil, fmt.Errorf("campos obligatorios no configurados: clientId, clientSecret, resource o host")
	}

	// Construir el formulario con los valores necesarios
	form := url.Values{}
	form.Set("client_id", c.ClientId)
	form.Set("client_secret", c.ClientSecret)
	form.Set("resource", c.Resource)
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "all") // Ajusta el scope según sea necesario

	// Construir la URL del endpoint
	urlStr := c.host + "/oidc/token"

	// Crear la solicitud HTTP POST
	req, err := http.NewRequest("POST", urlStr, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf(ErrCreatingRequest, err)
	}
	req.Header.Set(ContentTypeHeader, ApplicationForm)

	// Realizar la solicitud HTTP
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf(ErrPerformingRequest, err)
	}
	defer closeResponseBody(resp)

	// Leer el cuerpo de la respuesta para depuración
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf(ErrReadingResponse, err)
	}

	// Si el código de estado no es 200, devolver el cuerpo de la respuesta como parte del error
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(ErrRequestFailed, resp.StatusCode, string(bodyBytes))
	}

	// Decodificar la respuesta en la estructura TokenResponse
	var tokenResp TokenResponse
	if err := json.Unmarshal(bodyBytes, &tokenResp); err != nil {
		return nil, fmt.Errorf("error al decodificar la respuesta JSON: %w", err)
	}

	return &tokenResp, nil
}

// GetClientIdByToken obtiene el client_id de un token de Logto.
// tokenString: El token de Logto en formato JWS.
func (c *Client) GetClientIdByToken(tokenString string) (string, error) {
	// Validar el token JWS
	res := c.ValidateLogtoJWS(tokenString)

	// Deserializar el JSON devuelto por ValidateLogtoJWS
	var response map[string]interface{}
	if err := json.Unmarshal(res, &response); err != nil {
		fmt.Println("Error al deserializar el JSON:", err)
		return "", err
	}

	// Acceder al campo "data" y verificar si contiene "payload"
	data, ok := response["data"].(map[string]interface{})
	if !ok {
		fmt.Println("El campo 'data' no es un objeto JSON válido")
		return "", nil
	}

	// Acceder al campo "payload" dentro de "data"
	payload, ok := data["payload"].(map[string]interface{})
	if !ok {
		fmt.Println("El campo 'payload' no es un objeto JSON válido")
		return "", nil
	}

	// Acceder al campo "client_id" dentro del payload
	clientID, ok := payload["client_id"].(string)
	if !ok {
		fmt.Println("El campo 'client_id' no existe o no es una cadena")
		return "", nil
	}

	// Imprimir el valor de "client_id"
	return clientID, nil
}

// GetMetadata obtiene los datos personalizados de una aplicación y sus organizaciones.
// Retorna un string en formato JSON con los datos personalizados.
func (c *Client) GetMetadata(token string, applicationID string) (*Metadata, error) {
	// Obtener los datos de la aplicación
	app, err := c.GetMetaApplications(token, applicationID)
	if err != nil {
		return nil, fmt.Errorf("error al obtener los datos de la aplicación: %w", err)
	}

	// Obtener los datos de las organizaciones
	orgs, err := c.GetMetaOrganizations(token, applicationID)
	if err != nil {
		return nil, fmt.Errorf("error al obtener los datos de las organizaciones: %w", err)
	}

	// Extraer el customData de la aplicación
	appCustomData := app.CustomData

	// Extraer el customData de la primera organización (asumiendo que solo hay una)
	var orgCustomData map[string]interface{}
	if len(orgs) > 0 {
		orgCustomData = orgs[0].CustomData
	} else {
		orgCustomData = nil
	}

	// Construir la estructura Metadata
	metadata := &Metadata{
		App: appCustomData,
		Org: orgCustomData,
	}

	return metadata, nil
}

/* FUNCIONES PARA CONSUMIR EL SERVICIO DE LOGTO VIA HTTP */

// HandleTokenByClient maneja la solicitud HTTP para obtener un token.
// Los parámetros se pasan como variables (json o form) y se envían en formato x-www-form-urlencoded.
// router.HandleFunc("/logto/token", client.HandleTokenByClient)
func (c *Client) HandleTokenByClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, r, http.StatusMethodNotAllowed, "METODO_NO_PERMITIDO", "Método no permitido")
		return
	}

	contentType := r.Header.Get(ContentTypeHeader)
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		respondError(w, r, http.StatusBadRequest, "CONTENT_TYPE_INVALIDO", "Cabecera Content-Type inválida")
		return
	}

	var formData url.Values
	switch mediaType {
	case ApplicationJSON:
		formData, err = parseJSONBody(r)
		if err != nil {
			respondError(w, r, http.StatusBadRequest, "JSON_INVALIDO", "Error al decodificar JSON")
			return
		}
	case ApplicationForm:
		formData, err = parseFormBody(r)
		if err != nil {
			respondError(w, r, http.StatusBadRequest, "FORM_INVALIDO", "Error al parsear formulario")
			return
		}
	default:
		respondError(w, r, http.StatusUnsupportedMediaType, "MEDIA_TYPE_NO_SOPORTADO", "Tipo de contenido no soportado")
		return
	}

	headersCopy := make(http.Header)
	for k, v := range r.Header {
		if k != "Origin" {
			headersCopy[k] = v
		}
	}

	clientIP := getClientIP(r)
	tokenResp, err := c.GetTokenByClient(formData, headersCopy, clientIP, c.ClientResource, c.ClientScope)
	respondAuth(w, r, tokenResp, err)
}

// HandleTokenByClientGin Adaptada para usar gin.Context
// Maneja la solicitud HTTP para obtener un token.
// Los parámetros se pasan como variables y se envían en formato x-www-form-urlencoded.
func (c *Client) HandleTokenByClientGin(ctx *gin.Context) {
	contentType := ctx.GetHeader(ContentTypeHeader)

	var form url.Values
	var err error

	if contentType == ApplicationForm {
		if err := ctx.Request.ParseForm(); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error":   "FORM_INVALIDO",
				"message": "Error al parsear los parámetros del formulario",
			})
			return
		}
		form = ctx.Request.PostForm
	} else if contentType == ApplicationJSON {
		var jsonData map[string]string
		if err := ctx.ShouldBindJSON(&jsonData); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error":   "JSON_INVALIDO",
				"message": "Error al parsear el JSON",
			})
			return
		}

		form = make(url.Values)
		for key, value := range jsonData {
			form.Set(key, value)
		}
	} else {
		ctx.JSON(http.StatusUnsupportedMediaType, gin.H{
			"error":   "TIPO_CONTENIDO_NO_SOPORTADO",
			"message": "Tipo de contenido no soportado",
		})
		return
	}

	clientIP := getClientIP(ctx.Request)

	tokenResp, err := c.GetTokenByClient(form, ctx.Request.Header, clientIP, c.ClientResource, c.ClientScope)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "ERROR_INTERNO",
			"message": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, tokenResp)
}

// HandleApplications maneja la solicitud HTTP para obtener las aplicaciones.
// router.HandleFunc("/logto/applications", client.HandleApplications)
func (c *Client) HandleApplications(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, MethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	// Extraer el token del encabezado Authorization
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		respondError(w, r, http.StatusUnauthorized, "TOKEN_NO_PROPORCIONADO", TokenNotProvided)
		return
	}

	// Validar que el encabezado tenga el formato "Bearer <token>"
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		respondError(w, r, http.StatusUnauthorized, "FORMATO_TOKEN_INVALIDO", InvalidTokenFormat)
		return
	}
	token := parts[1]

	apps, err := c.GetApplications(token)
	respond(w, r, apps, err)
}

// HandleApplicationOrganizations maneja la solicitud HTTP para obtener las organizaciones de una aplicación.
// router.HandleFunc("/logto/applications/{id}/organizations", client.HandleApplicationOrganizations)
func (c *Client) HandleApplicationOrganizations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, MethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	appID := extractIDFromURL(r.URL.Path, "applications")
	if appID == "" {
		respondError(w, r, http.StatusBadRequest, "ID_APLICACION_INVALIDO", "ID de aplicación inválido")
		return
	}

	// Extraer el token del encabezado Authorization
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		respondError(w, r, http.StatusUnauthorized, "TOKEN_NO_PROPORCIONADO", TokenNotProvided)
		return
	}

	// Validar que el encabezado tenga el formato "Bearer <token>"
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		respondError(w, r, http.StatusUnauthorized, "FORMATO_TOKEN_INVALIDO", InvalidTokenFormat)
		return
	}
	token := parts[1]

	orgs, err := c.GetMetaOrganizations(token, appID)
	respondBasic(w, r, orgs, err)
}

// HandleOrganizations maneja la solicitud HTTP para obtener las organizaciones.
// router.HandleFunc("/logto/organizations", client.HandleOrganizations)
func (c *Client) HandleOrganizations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, MethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	// Extraer el token del encabezado Authorization
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		respondError(w, r, http.StatusUnauthorized, "TOKEN_NO_PROPORCIONADO", TokenNotProvided)
		return
	}

	// Validar que el encabezado tenga el formato "Bearer <token>"
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		respondError(w, r, http.StatusUnauthorized, "FORMATO_TOKEN_INVALIDO", InvalidTokenFormat)
		return
	}
	token := parts[1]

	orgs, err := c.GetOrganizations(token)
	respondBasic(w, r, orgs, err)
}

// HandleOrganizationApplications maneja la solicitud HTTP para obtener las aplicaciones de una organización.
// router.HandleFunc("/logto/organizations/{id}/applications", client.HandleOrganizationApplications)
func (c *Client) HandleOrganizationApplications(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, MethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	orgID := extractIDFromURL(r.URL.Path, "organizations")
	if orgID == "" {
		respondError(w, r, http.StatusBadRequest, "ID_ORGANIZACION_INVALIDO", "ID de organización inválido")
		return
	}

	// Extraer el token del encabezado Authorization
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		respondError(w, r, http.StatusUnauthorized, "TOKEN_NO_PROPORCIONADO", TokenNotProvided)
		return
	}

	// Validar que el encabezado tenga el formato "Bearer <token>"
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		respondError(w, r, http.StatusUnauthorized, "FORMATO_TOKEN_INVALIDO", InvalidTokenFormat)
		return
	}
	token := parts[1]

	orgs, err := c.GetOrganizationsApplication(token, orgID)
	respondBasic(w, r, orgs, err)
}

// ValidateLogtoJWS valida un token JWS y retorna un JSON con la estructura solicitada.
// En caso de error, se incluye el mensaje en data.error y se retorna nil en el error de Go.
func (c *Client) ValidateLogtoJWS(tokenString string) []byte {
	// 1. Validar caracteres del token
	if !isValidJWT(tokenString) {
		fmt.Printf("Error de token: formato inválido (caracteres no permitidos)\n")
		return makeErrorResponse("error de token: es inválido")
	}

	// 2. Dividir en partes
	parts := splitTokenParts(tokenString)
	if len(parts) != 3 {
		fmt.Printf("Error de token: la representación JWS debe contener exactamente tres partes\n")
		return makeErrorResponse("error de token: es inválido")
	}

	// 3. Decodificar header
	header, err := decodeHeader(parts[0])
	if err != nil {
		fmt.Printf("Error al decodificar el header del token: %v\n", err)
		return makeErrorResponse("error de token: es inválido")
	}

	// 4. Decodificar firma
	signatureBytes, err := decodeSignature(parts[2])
	if err != nil {
		fmt.Printf("Error al decodificar la firma del token: %v\n", err)
		return makeErrorResponse("error de token: es inválido")
	}

	// 5. Decodificar payload
	payload, err := decodePayload(parts[1])
	if err != nil {
		fmt.Printf("Error al decodificar el payload del token: %v\n", err)
		return makeErrorResponse("error de token: es inválido")
	}

	// 6. Obtener JWKS
	jwks, err := getJWKS(c.host)
	if err != nil {
		fmt.Printf("Error al obtener JWKS: %v\n", err)
		return makeResponse("error", "error de token: es inválido", nil, nil)
	}

	// 7. Validar 'kid' y 'alg' en el header
	headerKid, ok := header["kid"].(string)
	if !ok {
		fmt.Println("Error de token: el encabezado JWT no contiene 'kid'")
		return makeErrorResponse("error de token: es inválido")
	}
	headerAlg, ok := header["alg"].(string)
	if !ok {
		fmt.Println("Error de token: el encabezado JWT no contiene 'alg'")
		return makeErrorResponse("error de token: es inválido")
	}

	// 8. Buscar JWK correspondiente
	var matchingJWK *JWK
	for _, key := range jwks.Keys {
		if key.Kid == headerKid {
			if key.Use != "" && key.Use != "sig" {
				continue
			}
			if key.Alg != "" && key.Alg != headerAlg {
				continue
			}
			matchingJWK = &key
			break
		}
	}
	if matchingJWK == nil {
		fmt.Printf("Error de token: clave pública no encontrada para kid=%s, alg=%s\n", headerKid, headerAlg)
		return makeErrorResponse("error de token: es inválido")
	}

	// 9. Verificar firma
	signedData := parts[0] + "." + parts[1]
	if err := verifySignature(matchingJWK, headerAlg, signedData, signatureBytes); err != nil {
		fmt.Printf("Error de verificación de firma: %v\n", err)
		return makeErrorResponse("error de token: es inválido")
	}

	// 10. Validar expiración
	if !validateExpiration(payload) {
		exp, _ := payload["exp"].(float64)
		fmt.Printf("Error de token expirado: exp=%v\n", exp)
		return makeErrorResponse("error de token: ha expirado")
	}

	// 11. Validar issuer (iss)
	iss, ok := payload["iss"].(string)
	if !ok || iss != c.host+"/oidc" {
		fmt.Printf("Error de token: emisor (iss) inválido: %s\n", iss)
		return makeErrorResponse("error de token: es inválido")
	}

	return makeSuccessResponse(header, payload)
}

/* FUNCIONES AUXILIARES	*/

// Función parseResponse genérica que valida el status y decodifica la respuesta.
func parseResponse[T any](resp *http.Response) (T, error) {
	var result T
	if resp.StatusCode != http.StatusOK {
		return result, &HTTPError{StatusCode: resp.StatusCode, Status: resp.Status}
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return result, err
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return result, err
	}
	return result, nil
}

// Función respond escribe la respuesta en el formato estándar.
// Recibe el request para poder incluir la ruta (r.URL.Path) y la marca de tiempo.
func respond(w http.ResponseWriter, r *http.Request, data interface{}, err error) {
	w.Header().Set(ContentTypeHeader, ApplicationJSON)

	if err != nil {
		// Determinar el código de estado a partir del error.
		statusCode := http.StatusInternalServerError
		var httpErr *HTTPError
		if errors.As(err, &httpErr) {
			statusCode = httpErr.StatusCode
		}

		errorData := ErrorData{
			Code:    "ERROR", // Código genérico; se puede ajustar según el caso.
			Message: err.Error(),
			Time:    time.Now().UTC().Format(time.RFC3339),
			Route:   r.URL.Path,
		}
		standardResp := StandardResponse{
			Status: "error",
			Code:   statusCode,
			Data:   errorData,
		}
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(standardResp)
		return
	}

	// En caso de éxito se envuelve la data directamente.
	standardResp := StandardResponse{
		Status: "success",
		Code:   http.StatusOK,
		Data:   data,
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(standardResp)
}

func respondAuth(w http.ResponseWriter, r *http.Request, data interface{}, err error) {
	w.Header().Set(ContentTypeHeader, ApplicationJSON)

	if err != nil {
		var httpErr *HTTPError
		statusCode := http.StatusInternalServerError
		message := err.Error()

		// Extraer el código de estado y mensaje del error HTTP
		if errors.As(err, &httpErr) {
			statusCode = httpErr.StatusCode
			message = httpErr.Message
		}

		errorData := ErrorData{
			Code:    "ERROR",
			Message: message,
			Time:    time.Now().UTC().Format(time.RFC3339),
			Route:   r.URL.Path,
		}
		standardResp := StandardResponse{
			Status: "error",
			Code:   statusCode,
			Data:   errorData,
		}
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(standardResp)
		return
	}

	// En caso de éxito se envuelve la data directamente.
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(data)
}

func respondBasic(w http.ResponseWriter, r *http.Request, data interface{}, err error) {
	w.Header().Set(ContentTypeHeader, ApplicationJSON)

	if err != nil {
		// Determinar el código de estado a partir del error.
		statusCode := http.StatusInternalServerError
		var httpErr *HTTPError
		if errors.As(err, &httpErr) {
			statusCode = httpErr.StatusCode
		}

		errorData := ErrorData{
			Code:    "ERROR", // Código genérico; se puede ajustar según el caso.
			Message: err.Error(),
			Time:    time.Now().UTC().Format(time.RFC3339),
			Route:   r.URL.Path,
		}
		standardResp := StandardResponse{
			Status: "error",
			Code:   statusCode,
			Data:   errorData,
		}
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(standardResp)
		return
	}

	// En caso de éxito se envuelve la data directamente.
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(data)
}

// Función auxiliar para responder errores en el formato estándar sin necesidad de pasar un error.
func respondError(w http.ResponseWriter, r *http.Request, statusCode int, codigo, mensaje string) {
	w.Header().Set(ContentTypeHeader, ApplicationJSON)
	errorData := ErrorData{
		Code:    codigo,
		Message: mensaje,
		Time:    time.Now().UTC().Format(time.RFC3339),
		Route:   r.URL.Path,
	}
	standardResp := StandardResponse{
		Status: "error",
		Code:   statusCode,
		Data:   errorData,
	}
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(standardResp)
}

// Función auxiliar para extraer el ID de la URL dado el recurso.
func extractIDFromURL(path, resource string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == resource && len(parts) > i+1 {
			return parts[i+1]
		}
	}
	return ""
}

// getJWKS obtiene el conjunto de claves (JWKS) desde la URL indicada.
func getJWKS(jwksURL string) (*JWKS, error) {
	client := http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(jwksURL + "/oidc/jwks")
	if err != nil {
		return nil, err
	}
	defer closeResponseBody(resp)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jwks JWKS
	if err = json.Unmarshal(body, &jwks); err != nil {
		return nil, err
	}
	return &jwks, nil
}

// RSAKey convierte una JWK de tipo RSA a una clave pública RSA.
func (jwk *JWK) RSAKey() (*rsa.PublicKey, error) {
	// Decodificar el módulo (n) en base64url sin padding
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("error decodificando el módulo: %w", err)
	}
	// Decodificar el exponente (e)
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("error decodificando el exponente: %w", err)
	}
	// Convertir eBytes a entero (normalmente "AQAB" equivale a 65537)
	eInt := 0
	for _, b := range eBytes {
		eInt = eInt<<8 + int(b)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eInt,
	}, nil
}

// ECDSAKey convierte una JWK de tipo EC a una clave pública ECDSA.
func (jwk *JWK) ECDSAKey() (*ecdsa.PublicKey, error) {
	if jwk.Kty != "EC" {
		return nil, errors.New("la clave no es de tipo EC")
	}
	if jwk.Crv == "" || jwk.X == "" || jwk.Y == "" {
		return nil, errors.New("faltan parámetros EC en la JWK")
	}
	// Para ES384 se espera que la curva sea "P-384"
	if jwk.Crv != "P-384" {
		return nil, fmt.Errorf("curva no soportada: %s", jwk.Crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("error decodificando la coordenada X: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("error decodificando la coordenada Y: %w", err)
	}
	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P384(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}
	return pubKey, nil
}

// getClientIP obtiene la IP del cliente desde el encabezado X-Forwarded-For o RemoteAddr.
func getClientIP(req *http.Request) string {
	// Primero, intenta obtener la IP del encabezado X-Forwarded-For
	if forwardedFor := req.Header.Get(XForwardedForHeader); forwardedFor != "" {
		// El encabezado puede contener múltiples IPs; la primera es la del cliente original.
		ips := strings.Split(forwardedFor, ",")
		return strings.TrimSpace(ips[0])
	}

	// Si no hay X-Forwarded-For, usa RemoteAddr
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr // Fallback si no se puede dividir
	}
	return ip
}

func splitTokenParts(tokenString string) []string {
	return strings.Split(tokenString, ".")
}

func decodeHeader(encodedHeader string) (map[string]interface{}, error) {
	headerBytes, err := base64.RawURLEncoding.DecodeString(encodedHeader)
	if err != nil || !utf8.Valid(headerBytes) {
		return nil, err
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, err
	}
	return header, nil
}

func decodeSignature(encodedSignature string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(encodedSignature)
}

func decodePayload(encodedPayload string) (map[string]interface{}, error) {
	payloadBytes, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return nil, err
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func validateExpiration(payload map[string]interface{}) bool {
	exp, ok := payload["exp"].(float64)
	return ok && int64(exp) > time.Now().Unix()
}

func makeErrorResponse(message string) []byte {
	return makeResponse("error", message, nil, nil)
}

func makeSuccessResponse(header, payload map[string]interface{}) []byte {
	return makeResponse("success", "", header, payload)
}

// Función auxiliar para construir la respuesta JSON.
func makeResponse(status, msg string, header, payload map[string]interface{}) []byte {
	data := make(map[string]interface{})

	if status == "success" {
		data["header"] = header
		data["payload"] = payload
	} else {
		data["error"] = msg
	}

	resp := Response{
		Status: status,
		Data:   data,
	}

	b, _ := json.Marshal(resp)
	return b
}

func closeResponseBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		if err := resp.Body.Close(); err != nil {
			// Registra el error (por ejemplo, usando logs)
			fmt.Printf("Error al cerrar el cuerpo de la respuesta: %v\n", err)
		}
	}
}

// Función auxiliar para parsear el cuerpo JSON
func parseJSONBody(r *http.Request) (url.Values, error) {
	var jsonData map[string]interface{}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&jsonData); err != nil {
		return nil, err
	}

	formData := make(url.Values)
	for key, value := range jsonData {
		switch v := value.(type) {
		case string:
			formData.Set(key, v)
		case bool:
			formData.Set(key, strconv.FormatBool(v))
		case float64:
			formData.Set(key, strconv.FormatFloat(v, 'f', -1, 64))
		case []interface{}:
			for _, item := range v {
				formData.Add(key, fmt.Sprintf("%v", item))
			}
		default:
			formData.Set(key, fmt.Sprintf("%v", v))
		}
	}
	return formData, nil
}

// Función auxiliar para parsear el cuerpo form-urlencoded
func parseFormBody(r *http.Request) (url.Values, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	return r.PostForm, nil
}

// Función para verificar caracteres válidos en el token
func isValidJWT(token string) bool {
	for _, c := range token {
		if !isValidJWTChar(c) {
			return false
		}
	}
	return true
}

// Caracteres permitidos en JWT: letras, números, '-', '_', y '.'
func isValidJWTChar(c rune) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-' ||
		c == '_' ||
		c == '.'
}

// Función para verificar la firma criptográfica
func verifySignature(jwk *JWK, alg string, signedData string, signature []byte) error {
	switch jwk.Kty {
	case "RSA":
		publicKey, err := jwk.RSAKey()
		if err != nil {
			return fmt.Errorf("clave RSA inválida: %w", err)
		}
		return verifyRSASignature(publicKey, alg, signedData, signature)
	case "EC":
		publicKey, err := jwk.ECDSAKey()
		if err != nil {
			return fmt.Errorf("clave EC inválida: %w", err)
		}
		return verifyECDSASignature(publicKey, alg, signedData, signature)
	default:
		return fmt.Errorf("tipo de clave no soportado: %s", jwk.Kty)
	}
}

// Verificación RSA
func verifyRSASignature(pubKey *rsa.PublicKey, alg string, data string, signature []byte) error {
	hash := getHashAlgorithm(alg)
	hasher := hash.New()
	hasher.Write([]byte(data))
	hashed := hasher.Sum(nil)

	return rsa.VerifyPKCS1v15(pubKey, hash, hashed, signature)
}

// Verificación ECDSA
func verifyECDSASignature(pubKey *ecdsa.PublicKey, alg string, data string, signature []byte) error {
	hash := getHashAlgorithm(alg)
	hasher := hash.New()
	hasher.Write([]byte(data))
	hashed := hasher.Sum(nil)

	// La firma debe ser un par (r, s) concatenado
	keySize := pubKey.Curve.Params().BitSize / 8
	if len(signature) != 2*keySize {
		return fmt.Errorf("longitud de firma inválida")
	}

	r := new(big.Int).SetBytes(signature[:keySize])
	s := new(big.Int).SetBytes(signature[keySize:])

	if !ecdsa.Verify(pubKey, hashed, r, s) {
		return errors.New("firma EC inválida")
	}
	return nil
}

// Obtener algoritmo de hash
func getHashAlgorithm(alg string) crypto.Hash {
	switch alg {
	case "RS256", "ES256":
		return crypto.SHA256
	case "RS384", "ES384":
		return crypto.SHA384
	case "RS512", "ES512":
		return crypto.SHA512
	default:
		panic("algoritmo no soportado: " + alg)
	}
}
