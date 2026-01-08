#!/bin/bash

# LazySpringSecurity (LSS) - Script de Publicação JitPack
# Este script automatiza o processo de publicação do LSS no JitPack

set -e  # Sair em caso de erro

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Função para logging
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

warn() {
    echo -e "${YELLOW}[WARN] $1${NC}"
}

success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

info() {
    echo -e "${PURPLE}[INFO] $1${NC}"
}

# Banner
show_banner() {
    echo -e "${PURPLE}"
    echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    LazySpringSecurity (LSS) - JitPack Release                ║"
    echo "║                          github.com/abnerlourenco/lazy-spring-security       ║"
    echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Função para verificar pré-requisitos
check_prerequisites() {
    log "Verificando pré-requisitos para JitPack..."

    # Verificar se está no diretório correto
    if [ ! -f "pom.xml" ]; then
        error "Este script deve ser executado no diretório raiz do projeto (onde está o pom.xml)"
        exit 1
    fi

    # Verificar se Git está instalado
    if ! command -v git &> /dev/null; then
        error "Git não está instalado ou não está no PATH"
        exit 1
    fi

    # Verificar se Maven está instalado
    if ! command -v mvn &> /dev/null; then
        error "Maven não está instalado ou não está no PATH"
        exit 1
    fi

    # Verificar se está em um repositório Git
    if ! git rev-parse --git-dir &> /dev/null; then
        error "Não é um repositório Git válido"
        exit 1
    fi

    # Verificar se tem remote origin
    if ! git remote get-url origin &> /dev/null; then
        error "Repositório não tem remote 'origin' configurado"
        exit 1
    fi

    # Verificar se GroupId está correto para JitPack
    local groupId=$(mvn help:evaluate -Dexpression=project.groupId -q -DforceStdout)
    if [[ ! $groupId == com.github.jedin01 ]]; then
        warn "GroupId não está no formato esperado (com.github.jedin01)"
        warn "GroupId atual: $groupId"
        read -p "Deseja continuar mesmo assim? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi

    success "Pré-requisitos verificados"
}

# Função para obter informações do repositório
get_repo_info() {
    local remote_url=$(git remote get-url origin)

    # Extrair owner e repo do URL
    if [[ $remote_url =~ github\.com[:/]([^/]+)/([^/]+)(\.git)?$ ]]; then
        REPO_OWNER="${BASH_REMATCH[1]}"
        REPO_NAME="${BASH_REMATCH[2]}"
    else
        error "Não foi possível extrair informações do repositório GitHub"
        error "URL remoto: $remote_url"
        exit 1
    fi

    info "Repositório: $REPO_OWNER/$REPO_NAME"
}

# Função para obter a versão atual
get_current_version() {
    mvn help:evaluate -Dexpression=project.version -q -DforceStdout
}

# Função para executar testes
run_tests() {
    log "Executando testes..."
    mvn clean test -q
    success "Testes executados com sucesso"
}

# Função para verificar se está no branch correto
check_git_branch() {
    local current_branch=$(git branch --show-current)
    if [ "$current_branch" != "main" ] && [ "$current_branch" != "master" ]; then
        warn "Você não está no branch main/master (atual: $current_branch)"
        read -p "Deseja continuar mesmo assim? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Função para verificar mudanças não commitadas
check_git_status() {
    if [ -n "$(git status --porcelain)" ]; then
        warn "Há mudanças não commitadas no repositório"
        git status --short
        read -p "Deseja commitá-las automaticamente? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            git add .
            git commit -m "Prepare for JitPack release"
        else
            error "Por favor, commite as mudanças antes de continuar"
            exit 1
        fi
    fi
}

# Função para listar tags existentes
list_existing_tags() {
    log "Tags existentes:"
    git tag -l --sort=-version:refname | head -10
    echo
}

# Função para criar tag e fazer push
create_and_push_tag() {
    local version=$1
    local tag_name="v$version"

    log "Criando tag: $tag_name"

    # Verificar se tag já existe
    if git rev-parse "$tag_name" >/dev/null 2>&1; then
        warn "Tag $tag_name já existe"
        read -p "Deseja sobrescrever? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            git tag -d $tag_name
            git push origin --delete $tag_name 2>/dev/null || true
        else
            error "Tag não foi criada"
            return 1
        fi
    fi

    # Criar tag
    git tag -a $tag_name -m "JitPack release version $version"

    # Push para origin
    log "Fazendo push para GitHub..."
    git push origin main 2>/dev/null || git push origin master 2>/dev/null
    git push origin $tag_name

    success "Tag $tag_name criada e enviada para GitHub"

    # Mostrar informações do JitPack
    show_jitpack_info $tag_name
}

# Função para mostrar informações do JitPack
show_jitpack_info() {
    local tag=$1

    echo
    success "🎉 Release $tag publicado com sucesso!"
    echo
    info "📦 Informações do JitPack:"
    echo "   Repository: https://github.com/$REPO_OWNER/$REPO_NAME"
    echo "   JitPack URL: https://jitpack.io/#$REPO_OWNER/$REPO_NAME"
    echo "   Build Status: https://jitpack.io/com/github/$REPO_OWNER/$REPO_NAME/$tag/build.log"
    echo

    info "🔧 Para usar como dependência:"
    echo
    echo "   Maven:"
    echo "   <repositories>"
    echo "       <repository>"
    echo "           <id>jitpack.io</id>"
    echo "           <url>https://jitpack.io</url>"
    echo "       </repository>"
    echo "   </repositories>"
    echo
    echo "   <dependency>"
    echo "       <groupId>com.github.$REPO_OWNER</groupId>"
    echo "       <artifactId>$REPO_NAME</artifactId>"
    echo "       <version>$tag</version>"
    echo "   </dependency>"
    echo
    echo "   Gradle:"
    echo "   repositories {"
    echo "       maven { url 'https://jitpack.io' }"
    echo "   }"
    echo "   implementation 'com.github.$REPO_OWNER:$REPO_NAME:$tag'"
    echo

    warn "⏳ O build no JitPack pode levar alguns minutos. Aguarde antes de usar a dependência."
    echo
    read -p "🌐 Deseja abrir o JitPack no navegador? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if command -v open &> /dev/null; then
            open "https://jitpack.io/#$REPO_OWNER/$REPO_NAME"
        elif command -v xdg-open &> /dev/null; then
            xdg-open "https://jitpack.io/#$REPO_OWNER/$REPO_NAME"
        else
            info "Abra manualmente: https://jitpack.io/#$REPO_OWNER/$REPO_NAME"
        fi
    fi
}

# Função para sugerir próxima versão
suggest_next_version() {
    local current_version=$(get_current_version)

    # Remover 'v' prefix e '-SNAPSHOT' suffix se existir
    local clean_version=${current_version#v}
    clean_version=${clean_version%-SNAPSHOT}

    # Parse semantic version
    if [[ $clean_version =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
        local major="${BASH_REMATCH[1]}"
        local minor="${BASH_REMATCH[2]}"
        local patch="${BASH_REMATCH[3]}"

        local next_patch="$major.$minor.$((patch + 1))"
        local next_minor="$major.$((minor + 1)).0"
        local next_major="$((major + 1)).0.0"

        echo "Versão atual: $current_version"
        echo "Sugestões:"
        echo "  1) $next_patch (patch - correções)"
        echo "  2) $next_minor (minor - novas funcionalidades)"
        echo "  3) $next_major (major - breaking changes)"
        echo "  4) Versão customizada"
    else
        echo "Versão atual: $current_version"
        echo "Formato não reconhecido. Digite a nova versão manualmente."
    fi
}

# Menu principal
show_menu() {
    echo
    echo "======================================================================"
    echo "   LazySpringSecurity (LSS) - JitPack Release Script"
    echo "======================================================================"
    echo
    echo "Repositório: $REPO_OWNER/$REPO_NAME"
    echo "Versão atual: $(get_current_version)"
    echo
    echo "Opções:"
    echo "1) 🚀 Release Nova Versão"
    echo "2) 📋 Listar Tags Existentes"
    echo "3) 🧪 Executar Testes"
    echo "4) 🔍 Verificar Status Git"
    echo "5) 🌐 Abrir JitPack no Navegador"
    echo "6) ❌ Sair"
    echo
}

# Função para release
do_release() {
    echo
    suggest_next_version
    echo
    read -p "Digite a nova versão (sem 'v' prefix): " new_version

    if [ -z "$new_version" ]; then
        error "Versão não pode estar vazia"
        return 1
    fi

    # Validar formato semântico
    if [[ ! $new_version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
        warn "Versão não segue formato semântico (x.y.z)"
        read -p "Deseja continuar mesmo assim? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            return 1
        fi
    fi

    log "Iniciando release da versão $new_version..."

    check_git_status
    check_git_branch
    run_tests
    create_and_push_tag "$new_version"
}

# Função para abrir JitPack
open_jitpack() {
    local url="https://jitpack.io/#$REPO_OWNER/$REPO_NAME"
    info "Abrindo: $url"

    if command -v open &> /dev/null; then
        open "$url"
    elif command -v xdg-open &> /dev/null; then
        xdg-open "$url"
    elif command -v start &> /dev/null; then
        start "$url"
    else
        info "Por favor, abra manualmente: $url"
    fi
}

# Função principal
main() {
    show_banner
    check_prerequisites
    get_repo_info

    # Se argumentos foram passados, executar diretamente
    if [ $# -gt 0 ]; then
        case $1 in
            --release|-r)
                if [ -n "$2" ]; then
                    check_git_status
                    check_git_branch
                    run_tests
                    create_and_push_tag "$2"
                else
                    error "Uso: $0 --release <versao>"
                    exit 1
                fi
                ;;
            --test|-t)
                run_tests
                ;;
            --help|-h)
                echo "Uso: $0 [opção]"
                echo
                echo "Opções:"
                echo "  --release, -r <versao>   Release versão específica"
                echo "  --test, -t               Executar apenas testes"
                echo "  --help, -h               Mostrar esta ajuda"
                echo
                echo "Sem argumentos: modo interativo"
                ;;
            *)
                error "Opção desconhecida: $1"
                echo "Use $0 --help para ajuda"
                exit 1
                ;;
        esac
        return
    fi

    # Menu interativo
    while true; do
        show_menu
        read -p "Escolha uma opção (1-6): " choice

        case $choice in
            1)
                do_release
                ;;
            2)
                list_existing_tags
                ;;
            3)
                run_tests
                ;;
            4)
                git status
                ;;
            5)
                open_jitpack
                ;;
            6)
                log "Saindo..."
                exit 0
                ;;
            *)
                error "Opção inválida. Escolha entre 1-6."
                ;;
        esac

        echo
        read -p "Pressione Enter para continuar..."
    done
}

# Executar script
main "$@"
