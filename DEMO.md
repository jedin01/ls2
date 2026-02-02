# LazySpringSecurity - Demo Application

## 📍 Localização do Demo

A aplicação de demonstração completa do LazySpringSecurity está disponível na **branch `demo-app`** deste repositório:

🔗 **Branch: `demo-app`**

Para acessar:
```bash
git checkout demo-app
cd example-app
mvn spring-boot:run
```

### Extrair para Repositório Separado

Para mover o demo para um repositório separado (recomendado):

```bash
# 1. Checkout da branch demo-app
git checkout demo-app

# 2. Copiar example-app/ para novo diretório
cp -r example-app/ /path/to/lss-demo-app/

# 3. Criar novo repositório
cd /path/to/lss-demo-app/
git init
git add .
git commit -m "Initial commit: LSS demo application"
git remote add origin https://github.com/jedin01/lss-demo-app.git
git push -u origin main
```

## 🎯 Por Que em Repositório Separado?

Seguindo as melhores práticas de projetos Spring Boot:

1. **Separação de Responsabilidades**
   - O starter (ls2) contém apenas o código da biblioteca
   - O demo é uma aplicação independente que consome o starter

2. **Menor Tamanho do Repositório**
   - Mantém o repositório principal focado e limpo
   - Sem código de exemplo misturado com código de produção

3. **Exemplo Real de Uso**
   - Demonstra como um desenvolvedor real usaria o LSS
   - Mostra configuração de dependências correta
   - Não há acesso privilegiado ao código interno

4. **Segue Padrão Spring Boot**
   - `spring-boot-starter-*` não incluem demos no repositório principal
   - Exemplos ficam em repositórios separados ou na documentação

## 🚀 O Que o Demo Inclui

A aplicação demo demonstra **TODOS** os recursos do LazySpringSecurity:

### Recursos Demonstrados

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

### Estrutura do Demo

```
lss-demo-app/
├── README.md                    # Guia completo em português
├── pom.xml                      # Dependências do LSS
├── src/main/java/
│   ├── LssDemoApplication.java
│   ├── controller/
│   │   ├── AllFeaturesController.java    # 400+ linhas
│   │   ├── AuthController.java           # JWT auth
│   │   └── PublicEndpointsController.java
│   ├── model/
│   ├── dto/
│   └── service/
└── src/main/resources/
    └── application.properties
```

### Usuários Demo

| Username | Password | Roles         |
|----------|----------|---------------|
| admin    | admin123 | USER, ADMIN   |
| john     | john123  | USER          |
| jane     | jane123  | USER, MANAGER |

### Como Executar

```bash
git clone https://github.com/jedin01/lss-demo-app
cd lss-demo-app
mvn spring-boot:run
```

Aplicação disponível em: **http://localhost:8080**

## 📚 Documentação

O demo inclui:

- ✅ README completo com exemplos cURL
- ✅ Testes de cada recurso
- ✅ Script bash para teste automatizado
- ✅ Collection do Postman
- ✅ Guia de troubleshooting
- ✅ Tabela de comparação de recursos

## 🔄 Desenvolvimento Local

Se você quiser desenvolver localmente contra uma versão não publicada do LSS:

### 1. Instale o LSS localmente

```bash
cd /path/to/ls2
mvn clean install
```

### 2. Use no demo

```xml
<!-- pom.xml do demo -->
<dependency>
    <groupId>com.github.jedin01</groupId>
    <artifactId>lazy-spring-security-starter</artifactId>
    <version>1.1.0</version>
</dependency>
```

## 📖 Mais Exemplos

Além do demo principal, você pode encontrar exemplos específicos em:

- **USER_GUIDE.md** - Exemplos de código inline
- **ARCHITECTURE.md** - Exemplos arquiteturais
- **DEPENDENCY_GUIDE.md** - Exemplos de configuração

## 🤝 Contribuindo

Se você criar um exemplo interessante usando LSS:

1. Crie um repositório público
2. Adicione o tópico `lazy-spring-security` no GitHub
3. Abra uma issue no ls2 para compartilhar seu exemplo

Exemplos da comunidade são bem-vindos!

## 📞 Suporte

- **Issues**: https://github.com/jedin01/ls2/issues
- **Discussions**: https://github.com/jedin01/ls2/discussions
- **Demo Issues**: https://github.com/jedin01/lss-demo-app/issues

---

**Nota:** Este é o padrão seguido por todos os starters oficiais do Spring Boot. O código do starter fica em um repositório, exemplos e demos em outro(s).
