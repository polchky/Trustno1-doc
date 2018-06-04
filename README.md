# Trustno1

## Introduction
Trustno1 is an IoT middleware that guarantees data privacy using SGX enclaves. Clients (Things and users) exchange messages with the enclave using a REST API, encrypting encrypting all messages containing meaningful information so that no other party, including the server hosting the enclave, can read them. Intel provides a mechanism to attest that a client communicates with a genuine SGX enclave, containing the code and data it claims. 

## General Communication Protocols
The following protocol descriptions are generic, they can be used as-is for the front-end app. Messages are exchanged with the enclave using encryption over HTTP requests. Message encryption at the application layer is needed because the classical TLS encryption used by most for HTTP only ensures data confidentiality of exchanges up to the server, which in our system is an untrusted component. Application-layer encryption allows us to communicate securely up to the secure application running in the SGX enclave. 
The system uses JSON notation along with base64url encoding (to represent binary data). Note that spaces are allowed in JSON data structures (e.g. {"test": 1} and {"test":1} are both valid), and that base64url encoding gets rid of the "=" padding at the end of the representation (i.e. no "....==="). The Additional Authenticated Data (AAD) of encrypted messages are normally not included in the request (they are provided by the untrusted server to the enclave).

## Communication Using Session Keys
This type of communication assumes that the client and the enclave generated a shared and still valid session key. Normal messages exchange is done using symmetric encryption. Each request includes an "Authorization" header with a JWT (based on a JWE) token that authenticated the client. If present, the request payload is another JWE with normal serialization. For now, the encryption suite is considered fixed: AES-GCM 256 bits. The key size is 256 bits, the IV size is 96 bits and the tag length is 128 bits. A session is considered valid until either side decides to invalidate it. For each request, the used Initialization Vectors (IVs) must have a higher value that the ones used before. This is both a security measure and a way to ensure the order of the messages. 

### Authentication Token
The authenticating JWT is a JWE, present in the Authentication header of any request (Authorization: Bearer \<token\>). It is of the form:
```
BASE64URL-ENCODE(UTF8(JWE Header)) .
.
BASE64URL-ENCODE(JWE Initialization Vector) .
BASE64URL-ENCODE(JWE Claims) .
BASE64URL-ENCODE(JWE Authentication Tag)
```
The empty line is present because the JWT uses direct encryption, to no Content Encryption Key (cek) is present. The JWE header is defined as:
```
{"alg": "dir", "kid": <session key ID>, "cid": <client ID>}
```
The JWE claims set is defined (in its plaintext form) as: 
```
{
	"cid": <client ID>, 
	"mag": BASE64URL-ENCODE(<tag of message payload>)
}
```
The Message Tag (MAG) is only present in the case of a request containing a payload, and is used to link the header token to the request body. The IV must be higher that the ones used for previous messages of the same session, and must be higher than the one used for the request payload if present. The AAD used to generate the JWT consist in \<REST method\>:\<request path\>, for instance "GET:/clients/0123". They provide a check for any information that is not already included inside the header or the payload of the request, so that the enclave does not rely on any information given by the untrusted server only. 

### Message payload
If a payload is present in a request, it is represented as a JWE using flattened serialization. It is of the form: 
```
{
	"header": {"alg": "dir", "kid": <session key id>}, 
	"iv": BASE64URL-ENCODE(<iv>), 
	"ciphertext": BASE64URL-ENCODE(<ciphertext>), 
	"tag": BASE64URL-ENCODE(<tag>)
}
```
The Key ID (KID) is the same as the one used by the token. the IV value must be higher than the one used for the token. No AAD is used for the payload. The "tag" field is the one re-used by the authentication header as the "mag". The plaintext corresponding to the ciphertext is a JSON message containing the message from the client to the server, and are the ones described in the swagger API doc. 

### Server Response
The enclave provides a response for each request. It is always a JWE in the response payload, in the form:
```
{
	"header": {"alg": "dir", "kid": <session key id>}, 
	"iv": BASE64URL-ENCODE(<iv>), 
	"ciphertext": BASE64URL-ENCODE(<ciphertext>), 
	"tag": BASE64URL-ENCODE(<tag>)
}
```
The only exception is when there was no legitimate message sent to the server, in which case the server returns a code 401 Unauthorized, with no encrypted content. The IV must be greater than the ones used for the request. 
The ciphertext (in its plaintext form) consists in a JSON of the form:
```
{
	"mag": BASE64URL-ENCODE(<client's request authentication header tag>), 
	"message": <messsage>
}
```
The "message" field is not necessarily present. The AAD consist in the three digits string response code of the server (e.g. "201", "404").


## Proposed REST API
The REST API spec is provided in a separate document. In addition to HTTP status codes described in the document, each request can result in a **401** (unauthorized) response code with no response payload. This means the server was not able to decrypt the request, meaning either that an unauthorized client tried to make the request, or that the session key validity has expired. 
One note: the eventType and actionType resources provide a schema for event and action resources. However, there is no real obligation to check whether events and actions correspond to declared schemas. These resources can be seen as a way to simply categorize events and actions.

## Requirements for a Front-End Application
The system is based on the idea that the clients' privacy is assured, and that it is possible to prove it. Specifically, no code logic can ever be applied on clear data in untrusted platforms (any remote server). For the middleware this is solved by the use of attested SGX enclaves. On the client side, no particular architecture such as SGX is needed to guarantee privacy; the application logic consists of JS scripts running on the clients' machines and thus accessible to them. Because of that, the JS app is automatically trusted as it can be inspected by the clients. What differs from most JS apps is that **no client-related data can be stored in the clear on the server hosting the JS app**. Namely, any app configuration and meta data (e.g. the position of GUI elements) must be encrypted (using any encryption scheme as long as it is secure) before it is sent from the app to the untrusted server. One such example is that the client's private key cannot be stored on the server, and must be provided to the JS app by the user (file, manual input, ...). The front-end client must follow the specification described in this document. Other than that, there is no restriction on the extra possibilities and design of the application. Any extension to the current system can be done. If they require no server-side computation, the data containing extra features can be stored encrypted on the application server (e.g. GUI configuration). It is also possible to extend the current back-end system (enclave code), with discussion, to implement interesting new features. 

## Example Requests

### Request and Response
The following example shows how a request is constructed, sent, treated and responded to. In this example, a sensor client wants to post a new event to the enclave. 
- The client has the clientId 1, keyId 2, and uses eventTypeId 3. 
- The client wants to send the following properties: {"temperature": 20, "humidity": 35}.
- The hexadecimal representation of the session key is "60322a132f263fd64bd9dc6cdfb8c7512e7d093913d84baf7f986a10a4ef8692".
- The hexadecimal representation of the IV used for the message encryption is "0123456789abcdef01234568".
- The hexadecimal representation of the IV used for the authorization header encryption is "0123456789abcdef01234567". 

The client's procedure is as follow:
- The client creates the JSON object to be encrypted: 
	```
	{"clientId": 1, "eventTypeId": 3, "properties": {"temperature": 20, "humidity": 35}, "timestamp": "2018-06-03T14:34:46Z"}
	```
- The client creates the resulting JWE, which will be the payload of the request. Here is its representation: 
	```
	{
		"header": {"alg": "dir, "kid": 2},
		"ciphertext": "S0bi2ewjPc0H4wRl2wZkooBHajm1Zq3qozjX3ztTqsQkdbSP8jf-Blc2eg5iW3LfGq_yoeaR6yS1ZE1KHWyHWGNS4mrgaRJyScsFG8D7WGW_pmq_m9Ll0mdlN9IfqI-cPdr5XH--w_wS4IZXqbSsB8xY8NhbLYrclg", 
		"iv": "ASNFZ4mrze8BI0Vo", 
		"tag": "bokul3qgy5MQNnNnzlUBPQ"
	}
	```
- The client creates the JWT authentication header. The plaintext of the JWT claims is:
	 ```
	{"cid": 1, "mag": "bokul3qgy5MQNnNnzlUBPQ"}
	```
	The header if the JWT is (in JSON form):
	```
	{"alg": "dir", "kid": 2, "cid": 1}
	```
	The AAD are "POST:/events".
- Encrypting this payload, the resulting JWT is: 
	```
	eyJhbGciOiAiZGlyIiwgImtpZCI6IDIsICJjaWQiOiAxfQ..ASNFZ4mrze8BI0Vn.R7i2ZTomsmepayWtwZo-byrkmiGB9lymKb0nzXN7jrZR5ygPlaZOVF-mOQ.hD-VjO8oSIlOfpNM0UDdKw
	```
- The client sends a POST request to http://myapiaddress.com/api/events, using the generate JWT as a Bearer token in the headers (Authorization: Bearer \<token\>)

The server receives the request. Here is its procedure: 
- The server decodes the BASE64URL JWT fields.
- The server looks for a clientId and key ID matching those present in the JWT header.
- The server decrypts the JWT, and checks the validity of the cipher using the tag and the AAD. 
- The server now has authenticated the client. 
- The server checks that the "mag" of the JWT corresponds to the tag of the payload JWE.
- The server decrypts the payload and checks its integrity using the tag. 

At this point, the server can interpret the request (in this case create a new event). The server now creates a response as follow: 
- The server uses the same key and increments the IV by 1 ("0123456789abcdef01234569" in hexadecimal representation).
- The plaintext JSON the server will encrypt is: 
	```
	{"mag": "bokul3qgy5MQNnNnzlUBPQ", "message": {"id": 90, "clientId": 1, "eventTypeId": 3, "properties": {"temperature": 20, "humidity": 35}, "timestamp": "2018-06-03T14:34:46Z"}}
	```
- The server uses "201" as the AAD since it successfully created the resource.
- The resulting encoded JWE is:
	```
	{
		"header": {"alg": "dir, "kid": 2},
		"ciphertext": "69LOrohk1t7b0c3uAtzEJpT9b5X5soXfgy6wqYq_HQE_q4xvKisovXZ9tx9mJwRwHdbpDexK6XZuZ0xlnSuNDVqUg7cd86nuY8-0qoEjH6EaxH_ErSdIhn5FXkzbWvWtMa6pQL_EgSnPthAV1i1_X0hB-z0YesWfj04bAtVTj0RoN8SV2ll17iCqRC_d-VqkfF_Bl9Javw5LkxCiPL_Jgu-gFJYPmDjJYMl0ZM73-oG4", 
		"iv": "ASNFZ4mrze8BI0Vp", 
		"tag": "EZGftO8x2pwMz5mZBnLV6g"
	}
	```
The last step is for the client to check the response: 
- The client decrypts the message, checking its integrity using the tag and the response code as the AAD.
- The client checks that the message contains a "mag" field corresponding to its request tag. 
- The client deals with the response (in this case nothing to do, except increment the IV).

### API Resources
This example shows how to use the different resources of the API. Note that all the requests described here only show the decrypted payload of each request, and completely omit the encryption part that is systematically present.  We suppose we have an admin with ID 1, and a sensor client with ID 2. We also suppose that all registered clients have established a session key with the enclave. Each request is shown in one line, optionally followed by the payload description.
- The admin adds a new client that will act as an actuator: POST /clients
	```
	{
		"name": "actuator1",
		"pubKey": "xyzabc",
		"isAdmin": false,
		"isActive": false
	}
	```
	Server sends code 201, with new resource having ID 3.
- The admin wants to activate this client: PUT /clients/3
	```
	{
		"isActive": true
	}
	```
	Server sends code 200 with no content.
- The admin adds a new event type: POST /eventTypes
	```
	{
		"name": "temperatureEvent",
		"schema": {
			"type": "object",
			"properties": {
				"temperature": {
					"type": "integer"
				}
			},
			"required": ["temperature"]
		}
	}
	```
	The server sends code 201, with resource having ID 1. 
- The admin adds a new action type: POST /actionTypes
	```
	{
		"name": "TemperatureAction",
		"schema": {
			"type": "object",
			"properties": {
				"temperature": {
					"type": "integer"
				},
				"message": {
					"type": "string"
				}
			},
			"required": ["temperature"]
		}
	}
	```
	The server sends code 201, with resource having ID 1.
- The admin adds a new rule so that each time client 2 sends a temperature value higher that 25, the client 3 is notified: POST /rules
	```
	{
		"eventTypeIds": [1],
		"sourceClientIds": [2],
		"function": "if(event.temperature > 25){return {temperature: event.temperature, message: \"It's gonna be hot today!\"}}else{return null}",
		"actionTypeIds": [1],
		"destClientIds": [3],
		"destUrlIds": [],
		"isActive": true
	}
	```
	The server sends code 201, with rule having ID 1. 
- The sensor client adds a new event: POST /events
	```
	{
		"clientId": 2,
		"eventTypeId": 1,
		"properties": {"temperature": 26},
		"timestamp": "2018-06-03T14:34:46Z"
	}
	```
	The server sends code 201 with event having ID 1.
- The actuator client randomly checks its action messages: GET /clients/3/actionMessages
	The server sends code 200 with the following payload (response payload was omitted for previous requests):
	```
	[
		{
			"id": 1,
			"eventId": 1,
			"ruleId": 1,
			"actionTypId": 1,
			"message": {
				"temperature": 26,
				"message": "It's gonna be hot today!"
			},
			"destClientId": 3,
			"completionTime": null
		}
	]
	```
- The actuator client notifies the server that he received the action: PUT /clients/3/actionMessages/1
	```
	{
		"completionTime": "2018-06-03T15:37:24Z"
	}
	```
	The server sends code 200. 

This peculiar way of acknowledging actions is used in order to respect the RESTful principles (a GET is idempotent, a POST creates a resource, etc.).
## References
- JWT: 
https://tools.ietf.org/html/rfc7519
- JWE: 
https://tools.ietf.org/html/rfc7516
- JSON Schema: 
https://spacetelescope.github.io/understanding-json-schema/index.html
