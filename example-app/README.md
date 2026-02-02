# LazySpringSecurity - Complete Features Demo

🎯 **Esta aplicação demonstra TODOS os recursos do LazySpringSecurity!**

## 📋 Recursos Demonstrados

Este demo mostra todos os recursos do LSS em ação:

1. ✅ **@Public** - Endpoints públicos sem autenticação
2. ✅ **@Secured** - Autenticação obrigatória
3. ✅ **@Secured("ROLE")** - Autorização baseada em roles
4. ✅ **@Owner** - Verificação de propriedade de recursos
5. ✅ **@RateLimit** - Limitação de taxa de requisições
6. ✅ **@Cached** - Cache de respostas
7. ✅ **@Audit** - Logging de auditoria
8. ✅ **LazyAuth** - API utilitária
9. ✅ **LazyUser** - Injeção automática de usuário
10. ✅ **JWT** - Autenticação completa com tokens
11. ✅ **@Valid** - Validação de entrada

## 🚀 Como Executar

### Opção 1: Maven

```bash
cd example-app
mvn spring-boot:run
```

### Opção 2: JAR

```bash
cd example-app
mvn clean package
java -jar target/lss-demo-app-1.0.0.jar
```

A aplicação estará disponível em: **http://localhost:8080**

## 👥 Usuários Demo (criados automaticamente)

| Username | Password   | Roles         |
|----------|------------|---------------|
| admin    | admin123   | USER, ADMIN   |
| john     | john123    | USER          |
| jane     | jane123    | USER, MANAGER |

## 📚 Testando os Recursos

### 1. Endpoints Públicos (@Public)

**Nenhuma autenticação necessária!**

```bash
# Health check
curl http://localhost:8080/api/health

# Informações da aplicação
curl http://localhost:8080/api/info

# Listar produtos públicos
curl http://localhost:8080/api/public/products
```

### 2. Registro e Login (JWT)

**Registrar novo usuário:**
```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "password123"
  }'
```

**Login:**
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin123"
  }'
```

**Resposta:**
```json
{
  "message": "✅ Login successful",
  "access_token": "eyJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiJ9...",
  "expires_in": 900,
  "user": {
    "id": "1",
    "username": "admin",
    "roles": ["USER", "ADMIN"]
  }
}
```

**⚠️ Copie o `access_token` para usar nos próximos comandos!**

### 3. Endpoints Autenticados (@Secured)

**Dashboard (qualquer usuário autenticado):**
```bash
curl http://localhost:8080/api/dashboard \
  -H "Authorization: Bearer SEU_ACCESS_TOKEN_AQUI"
```

**Perfil com LazyAuth API:**
```bash
curl http://localhost:8080/api/profile \
  -H "Authorization: Bearer SEU_ACCESS_TOKEN_AQUI"
```

### 4. Autorização por Roles (@Secured("ROLE"))

**Admin Stats (apenas ADMIN):**
```bash
# Como admin (funciona ✅)
curl http://localhost:8080/api/admin/stats \
  -H "Authorization: Bearer ADMIN_TOKEN"

# Como john (falha ❌ - não tem role ADMIN)
curl http://localhost:8080/api/admin/stats \
  -H "Authorization: Bearer JOHN_TOKEN"
```

**Reports (ADMIN ou MANAGER):**
```bash
curl http://localhost:8080/api/reports \
  -H "Authorization: Bearer SEU_TOKEN"
```

### 5. Propriedade de Recursos (@Owner)

**Pedidos do usuário (só vê os próprios):**
```bash
# John acessando seus próprios pedidos (funciona ✅)
curl http://localhost:8080/api/users/2/orders \
  -H "Authorization: Bearer JOHN_TOKEN"

# John tentando acessar pedidos de outro usuário (falha ❌)
curl http://localhost:8080/api/users/1/orders \
  -H "Authorization: Bearer JOHN_TOKEN"
```

**Dados sensíveis (com adminBypass):**
```bash
# Usuário vê seus próprios dados
curl http://localhost:8080/api/users/2/sensitive-data \
  -H "Authorization: Bearer JOHN_TOKEN"

# Admin pode ver dados de qualquer um
curl http://localhost:8080/api/users/2/sensitive-data \
  -H "Authorization: Bearer ADMIN_TOKEN"
```

**Editar post (apenas o criador):**
```bash
# Primeiro, criar um post
curl -X POST http://localhost:8080/api/posts \
  -H "Authorization: Bearer SEU_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Meu Post",
    "content": "Conteúdo do post"
  }'

# Editar o post (apenas o criador pode)
curl -X PUT http://localhost:8080/api/posts/1 \
  -H "Authorization: Bearer SEU_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Título Atualizado"
  }'
```

### 6. Rate Limiting (@RateLimit)

**Endpoint com limite (5 requisições por minuto):**
```bash
# Execute este comando 6 vezes seguidas
curl http://localhost:8080/api/limited

# Na 6ª vez, você receberá erro 429 (Too Many Requests)
```

**Upload com limite por usuário:**
```bash
# Cada usuário tem seu próprio limite (10/min)
curl -X POST http://localhost:8080/api/upload \
  -H "Authorization: Bearer SEU_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"file": "data"}'
```

### 7. Cache (@Cached)

**Dados com cache (5 minutos):**
```bash
# Primeira chamada - calcula valor
curl http://localhost:8080/api/cached-data

# Segunda chamada - retorna do cache (mesmo valor!)
curl http://localhost:8080/api/cached-data

# Espere 5 minutos e chame novamente - novo valor
```

**Cache por usuário:**
```bash
# John chama
curl http://localhost:8080/api/user-cached-data \
  -H "Authorization: Bearer JOHN_TOKEN"

# Jane chama - recebe valor diferente (cache separado)
curl http://localhost:8080/api/user-cached-data \
  -H "Authorization: Bearer JANE_TOKEN"
```

### 8. Auditoria (@Audit)

**Endpoint auditado:**
```bash
# Todos os acessos são logados
curl http://localhost:8080/api/admin/users \
  -H "Authorization: Bearer ADMIN_TOKEN"

# Verifique os logs da aplicação!
```

**Operação crítica (HIGH level):**
```bash
curl -X DELETE http://localhost:8080/api/admin/users/2 \
  -H "Authorization: Bearer ADMIN_TOKEN"

# Log registra: quem deletou, quando, qual usuário
```

### 9. Múltiplos Recursos Combinados

**Criar post (Secured + RateLimit + Audit):**
```bash
curl -X POST http://localhost:8080/api/posts \
  -H "Authorization: Bearer SEU_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Teste LSS",
    "content": "Demonstração de múltiplos recursos"
  }'
```

**Todos os recursos em um endpoint:**
```bash
# Secured + RateLimit + Cached + Audit
curl http://localhost:8080/api/demo/all-features \
  -H "Authorization: Bearer ADMIN_TOKEN"
```

### 10. Refresh Token

**Renovar access token:**
```bash
curl -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "SEU_REFRESH_TOKEN_AQUI"
  }'
```

## 🧪 Scripts de Teste

### Script Bash Completo

```bash
#!/bin/bash

BASE_URL="http://localhost:8080/api"

echo "🚀 Testando LazySpringSecurity Demo"
echo "======================================"

# 1. Health check
echo -e "\n1️⃣ Testing @Public endpoint..."
curl -s $BASE_URL/health | jq

# 2. Login
echo -e "\n2️⃣ Testing JWT Login..."
LOGIN_RESPONSE=$(curl -s -X POST $BASE_URL/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}')
echo $LOGIN_RESPONSE | jq

TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.access_token')
echo "Token: $TOKEN"

# 3. Authenticated endpoint
echo -e "\n3️⃣ Testing @Secured endpoint..."
curl -s $BASE_URL/dashboard \
  -H "Authorization: Bearer $TOKEN" | jq

# 4. Role-based authorization
echo -e "\n4️⃣ Testing @Secured(\"ADMIN\")..."
curl -s $BASE_URL/admin/stats \
  -H "Authorization: Bearer $TOKEN" | jq

# 5. Rate limiting
echo -e "\n5️⃣ Testing @RateLimit..."
for i in {1..6}; do
  echo "Request $i:"
  curl -s $BASE_URL/limited | jq '.message'
done

# 6. Caching
echo -e "\n6️⃣ Testing @Cached..."
echo "First call:"
curl -s $BASE_URL/cached-data | jq '.computedValue'
echo "Second call (should be same):"
curl -s $BASE_URL/cached-data | jq '.computedValue'

# 7. All features
echo -e "\n7️⃣ Testing all features combined..."
curl -s $BASE_URL/demo/all-features \
  -H "Authorization: Bearer $TOKEN" | jq

echo -e "\n✅ Tests completed!"
```

Salve como `test-lss.sh` e execute:
```bash
chmod +x test-lss.sh
./test-lss.sh
```

### Teste com Postman

Importe esta collection:

```json
{
  "info": {
    "name": "LazySpringSecurity Demo",
    "description": "Complete LSS features demonstration"
  },
  "item": [
    {
      "name": "1. Login",
      "request": {
        "method": "POST",
        "url": "http://localhost:8080/api/auth/login",
        "body": {
          "mode": "raw",
          "raw": "{\"username\":\"admin\",\"password\":\"admin123\"}"
        }
      }
    },
    {
      "name": "2. Dashboard (@Secured)",
      "request": {
        "method": "GET",
        "url": "http://localhost:8080/api/dashboard",
        "header": [
          {"key": "Authorization", "value": "Bearer {{token}}"}
        ]
      }
    },
    {
      "name": "3. Admin Stats (@Secured ADMIN)",
      "request": {
        "method": "GET",
        "url": "http://localhost:8080/api/admin/stats",
        "header": [
          {"key": "Authorization", "value": "Bearer {{token}}"}
        ]
      }
    }
  ]
}
```

## 📖 Código-Fonte

### Estrutura do Projeto

```
example-app/
├── pom.xml                              # Maven configuration
├── src/main/java/com/example/lss/demo/
│   ├── LssDemoApplication.java          # Main application
│   ├── controller/
│   │   ├── PublicEndpointsController.java       # @Public demos
│   │   ├── AllFeaturesController.java           # All LSS features
│   │   └── AuthController.java                  # JWT authentication
│   ├── model/
│   │   ├── User.java
│   │   ├── Post.java
│   │   ├── Order.java
│   │   └── Product.java
│   ├── dto/
│   │   ├── RegisterRequest.java
│   │   └── LoginRequest.java
│   └── service/
│       └── UserService.java
└── src/main/resources/
    └── application.properties
```

### Exemplo de Uso no Código

Veja `AllFeaturesController.java` para exemplos de cada recurso:

```java
// 1. Endpoint público
@Public
@GetMapping("/health")
public ResponseEntity<?> health() { ... }

// 2. Autenticação obrigatória
@Secured
@GetMapping("/dashboard")
public ResponseEntity<?> dashboard(LazyUser user) { ... }

// 3. Role específica
@Secured("ADMIN")
@GetMapping("/admin/stats")
public ResponseEntity<?> stats() { ... }

// 4. Verificação de propriedade
@Owner(field = "userId")
@GetMapping("/users/{userId}/orders")
public ResponseEntity<?> orders(@PathVariable String userId) { ... }

// 5. Rate limiting
@RateLimit(requests = 5, windowInSeconds = 60)
@GetMapping("/limited")
public ResponseEntity<?> limited() { ... }

// 6. Cache
@Cached(ttl = 300)
@GetMapping("/cached-data")
public ResponseEntity<?> cached() { ... }

// 7. Auditoria
@Audit(action = "VIEW_DATA")
@GetMapping("/data")
public ResponseEntity<?> data() { ... }

// 8. Múltiplos recursos
@Secured
@RateLimit(requests = 3, windowInSeconds = 60)
@Audit(action = "CREATE")
@PostMapping("/posts")
public ResponseEntity<?> create() { ... }
```

## 🎯 Recursos LSS por Endpoint

| Endpoint | @Public | @Secured | @Owner | @RateLimit | @Cached | @Audit |
|----------|---------|----------|--------|------------|---------|--------|
| `/api/health` | ✅ | - | - | - | - | - |
| `/api/dashboard` | - | ✅ | - | - | - | - |
| `/api/admin/stats` | - | ✅ ADMIN | - | - | - | - |
| `/api/users/{id}/orders` | - | ✅ | ✅ | - | - | - |
| `/api/limited` | ✅ | - | - | ✅ | - | - |
| `/api/cached-data` | ✅ | - | - | - | ✅ | - |
| `/api/admin/users` | - | ✅ ADMIN | - | - | - | ✅ |
| `/api/posts` | - | ✅ | - | ✅ | - | ✅ |
| `/api/demo/all-features` | - | ✅ ADMIN | - | ✅ | ✅ | ✅ |

## 💡 Dicas

1. **Tokens expiram em 15 minutos** - Use refresh token para renovar
2. **Rate limits são por IP** - Para `perUser=true`, são por usuário autenticado
3. **Cache é em memória** - Reiniciar a app limpa o cache
4. **Logs de audit** - Veja no console da aplicação
5. **Teste com múltiplos usuários** - Use admin, john e jane para ver diferentes comportamentos

## 🐛 Troubleshooting

**Token inválido?**
```
Faça login novamente - tokens expiram em 15 minutos
```

**403 Forbidden?**
```
Verifique se seu usuário tem a role necessária
admin = ADMIN, john = USER, jane = MANAGER
```

**429 Too Many Requests?**
```
Aguarde 1 minuto - você excedeu o rate limit
```

**Mesmo valor no cache?**
```
Normal! Cache dura 5 minutos. Aguarde ou reinicie a app.
```

## 📝 Próximos Passos

1. Explore o código em `AllFeaturesController.java`
2. Tente criar seus próprios endpoints com LSS
3. Experimente combinar múltiplos recursos
4. Veja a documentação completa no projeto principal

## 🎉 Conclusão

Este demo mostra que com LazySpringSecurity você pode:

- ✅ Proteger endpoints com 1 linha: `@Secured`
- ✅ Implementar rate limiting com 1 linha: `@RateLimit`
- ✅ Adicionar cache com 1 linha: `@Cached`
- ✅ Logar auditorias com 1 linha: `@Audit`
- ✅ Verificar propriedade com 1 linha: `@Owner`

**Total: 95% menos código que Spring Security tradicional!**

---

**Criado por:** LazySpringSecurity Team  
**Versão:** 1.0.0  
**Licença:** MIT
