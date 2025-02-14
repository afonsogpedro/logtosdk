package logtosdk

import (
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
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// HTTPError es un error personalizado que incluye el código de estado HTTP.
type HTTPError struct {
	StatusCode int
	Status     string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("Error en la solicitud: %s", e.Status)
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
		// Si ya existe un X-Forwarded-For, agregamos la nueva IP al inicio.
		existingForwardedFor := req.Header.Get(XForwardedForHeader)
		if existingForwardedFor != "" {
			clientIP = clientIP + ", " + existingForwardedFor
		}
		req.Header.Set(XForwardedForHeader, clientIP)
	}

	// Aseguramos que el Content-Type sea correcto.
	req.Header.Set(ContentTypeHeader, "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf(ErrPerformingRequest, err)
	}
	defer closeResponseBody(resp)

	// Se utiliza parseResponse para decodificar la respuesta en la estructura TokenResponse.
	tokenResp, err := parseResponse[TokenResponse](resp)
	if err != nil {
		return nil, err
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
	req.Header.Set(ContentTypeHeader, "application/x-www-form-urlencoded")

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
// Los parámetros se pasan como variables y se envían en formato x-www-form-urlencoded.
// router.HandleFunc("/logto/token", client.HandleTokenByClient)
func (c *Client) HandleTokenByClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, r, http.StatusMethodNotAllowed, "METODO_NO_PERMITIDO", MethodNotAllowed)
		return
	}

	// Parseamos los parámetros enviados en el formulario.
	if err := r.ParseForm(); err != nil {
		respondError(w, r, http.StatusBadRequest, "FORM_INVALIDO", "Error al parsear los parámetros del formulario")
		return
	}

	form := r.PostForm

	// Obtener la IP del cliente original
	clientIP := getClientIP(r)

	// Pasamos los encabezados de la solicitud original a GetTokenByClient.
	tokenResp, err := c.GetTokenByClient(form, r.Header, clientIP, c.ClientResource, c.ClientScope)
	respondBasic(w, r, tokenResp, err)
}

// Adaptada para usar gin.Context
// HandleTokenByClient maneja la solicitud HTTP para obtener un token.
// Los parámetros se pasan como variables y se envían en formato x-www-form-urlencoded.
func (c *Client) HandleTokenByClientGin(ctx gin.Context) {
	contentType := ctx.GetHeader("Content-Type")

	var form map[string][]string
	var err error

	if contentType == "application/x-www-form-urlencoded" {
		if err := ctx.Request.ParseForm(); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error":   "FORM_INVALIDO",
				"message": "Error al parsear los parámetros del formulario",
			})
			return
		}
		form = ctx.Request.PostForm
	} else if contentType == "application/json" {
		if err := ctx.ShouldBindJSON(&form); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error":   "JSON_INVALIDO",
				"message": "Error al parsear el JSON",
			})
			return
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
	parts := splitTokenParts(tokenString)
	if len(parts) != 3 {
		return makeErrorResponse("la representación JWS debe contener exactamente tres partes")
	}

	header, err := decodeHeader(parts[0])
	if err != nil {
		return makeErrorResponse(fmt.Sprintf("error decodificando el header: %v", err))
	}

	_, err = decodeSignature(parts[2])
	if err != nil {
		return makeErrorResponse(fmt.Sprintf("error decodificando la firma: %v", err))
	}

	payload, err := decodePayload(parts[1])
	if err != nil {
		return makeErrorResponse(fmt.Sprintf("error decodificando el payload: %v", err))
	}

	jwks, err := getJWKS(c.host)
	if err != nil {
		return makeResponse("error", fmt.Sprintf("error obteniendo JWKS: %v", err), nil, nil)
	}
	var matchingJWK *JWK
	for _, key := range jwks.Keys {
		if key.Kid == header["kid"].(string) {
			matchingJWK = &key
			break
		}
	}
	if matchingJWK == nil {
		return makeResponse("error", "clave pública no encontrada para el kid especificado", nil, nil)
	}

	if !validateExpiration(payload) {
		return makeErrorResponse("el token ha expirado")
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
