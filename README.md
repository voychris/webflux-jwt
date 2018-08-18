# webflux-jwt
Example of securing a webflux application with JWT.

By default all endpoints under `/api/**` are secured with `api:read` permission. 
This behaviour can be changed in `SecurityConfiguration`.


#### Running the application
`./gradlew bootRun`

Testing:
```bash
curl -v \
-H "Authorization: Bearer <token>" \
localhost:8080/api/sample
```

#### Generating JWT

 - default secret is `secret`
 - default aud is `secured-api`
 - payload:
 
```json
{
  "aud": "secured-api",
  "sub": "client",
  "perms": [
    "api:read"
  ]
}
```
