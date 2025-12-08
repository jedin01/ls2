#!/usr/bin/env fish

# ============================================================================
# 🔐 LazySpringSecurity - Script de Teste
# ============================================================================
# 
# Este script demonstra como usar a API do LSS Demo.
# Execute a aplicação primeiro:
#   ./mvnw spring-boot:run -Dspring-boot.run.main-class=ao.sudojed.lss.demo.DemoApplication
#
# Depois execute este script:
#   fish test-api.fish
# ============================================================================

set BASE_URL "http://localhost:8080"

echo "
╔═══════════════════════════════════════════════════════════════╗
║          🔐 LazySpringSecurity - Testes de API 🔐             ║
╚═══════════════════════════════════════════════════════════════╝
"

# ============================================================================
echo "📢 1. HEALTH CHECK (Público)"
echo "─────────────────────────────────────────────"
curl -s "$BASE_URL/auth/health" | jq .
echo ""

# ============================================================================
echo "📢 2. REGISTRO DE NOVO USUÁRIO (Público)"
echo "─────────────────────────────────────────────"
curl -s -X POST "$BASE_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username": "teste", "email": "teste@example.com", "password": "senha123"}' | jq .
echo ""

# ============================================================================
echo "🔐 3. LOGIN COMO USUÁRIO NORMAL"
echo "─────────────────────────────────────────────"
set LOGIN_RESPONSE (curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "john", "password": "123456"}')
echo $LOGIN_RESPONSE | jq .

# Extrai o token
set USER_TOKEN (echo $LOGIN_RESPONSE | jq -r '.access_token')
echo ""
echo "🎫 Token do usuário: "(string sub -l 50 $USER_TOKEN)"..."
echo ""

# ============================================================================
echo "🔐 4. ACESSAR PERFIL (Autenticado)"
echo "─────────────────────────────────────────────"
curl -s "$BASE_URL/api/profile" \
  -H "Authorization: Bearer $USER_TOKEN" | jq .
echo ""

# ============================================================================
echo "🔐 5. ACESSAR /api/me (Autenticado)"
echo "─────────────────────────────────────────────"
curl -s "$BASE_URL/api/me" \
  -H "Authorization: Bearer $USER_TOKEN" | jq .
echo ""

# ============================================================================
echo "🔐 6. LISTAR MEUS PEDIDOS (Autenticado)"
echo "─────────────────────────────────────────────"
curl -s "$BASE_URL/api/orders" \
  -H "Authorization: Bearer $USER_TOKEN" | jq .
echo ""

# ============================================================================
echo "❌ 7. TENTAR ACESSAR ADMIN SEM SER ADMIN"
echo "─────────────────────────────────────────────"
echo "Esperado: 403 Forbidden"
curl -s "$BASE_URL/api/admin/users" \
  -H "Authorization: Bearer $USER_TOKEN" | jq .
echo ""

# ============================================================================
echo "👑 8. LOGIN COMO ADMIN"
echo "─────────────────────────────────────────────"
set ADMIN_RESPONSE (curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}')
set ADMIN_TOKEN (echo $ADMIN_RESPONSE | jq -r '.access_token')
echo "🎫 Token do admin: "(string sub -l 50 $ADMIN_TOKEN)"..."
echo ""

# ============================================================================
echo "👑 9. LISTAR TODOS USUÁRIOS (Admin)"
echo "─────────────────────────────────────────────"
curl -s "$BASE_URL/api/admin/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
echo ""

# ============================================================================
echo "👑 10. DASHBOARD ADMIN"
echo "─────────────────────────────────────────────"
curl -s "$BASE_URL/api/admin/dashboard" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
echo ""

# ============================================================================
echo "🔐 11. CRIAR PEDIDO"
echo "─────────────────────────────────────────────"
curl -s -X POST "$BASE_URL/api/orders" \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"product": "Headphone Gamer", "quantity": 2, "price": 299.99}' | jq .
echo ""

# ============================================================================
echo "❌ 12. TENTAR ACESSAR SEM TOKEN"
echo "─────────────────────────────────────────────"
echo "Esperado: 401 Unauthorized"
curl -s "$BASE_URL/api/profile" | jq .
echo ""

echo "
╔═══════════════════════════════════════════════════════════════╗
║                    ✅ Testes Concluídos!                      ║
╚═══════════════════════════════════════════════════════════════╝
"
