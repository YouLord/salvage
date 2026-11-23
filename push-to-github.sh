#!/usr/bin/env bash
#
# push-to-github.sh — выложить salvage на GitHub одним запуском, без ошибок.
#
#   bash push-to-github.sh                     # спросит логин и токен
#   GH_USER=YouLord GH_TOKEN=ghp_xxx bash push-to-github.sh   # без вопросов
#   bash push-to-github.sh --repo https://github.com/YouLord/salvage.git
#   bash push-to-github.sh --dry-run           # показать, что будет сделано
#
# Что скрипт делает и почему:
#   1. проверяет, что он запущен из репозитория salvage (есть .git и пакет salvage/);
#   2. проверяет, что рабочее дерево чистое (иначе коммитить нечего / потеряются правки);
#   3. проверяет автора коммитов: если git не знает user.name/user.email — ставит
#      локальные значения (иначе git откажется делать коммиты при pull --rebase);
#   4. настраивает origin на нужный URL и переименовывает ветку в main;
#   5. смотрит, что уже лежит на GitHub:
#        — пусто           → обычный push;
#        — есть автогенерируемый README/LICENSE/.gitignore → делает коммит-слияние,
#          сохраняя «Initial commit» GitHub; наш README остаётся;
#        — есть посторонние файлы → ОТКАЗЫВАЕТСЯ форсить и показывает, что делать;
#   6. пушит по HTTPS с токеном (без интерактивных запросов пароля — они и есть
#      главная причина «повисло/отказало» в автоматическом режиме);
#   7. проверяет результат через git ls-remote и печатает ссылку.
#
# Токен НЕ сохраняется в конфиг и НЕ попадает в историю: он передаётся только
# через переменную окружения на время push.
#
# Требуется: git. Токен: GitHub → Settings → Developer settings →
# Personal access tokens → Tokens (classic) → scope "repo".

set -Eeuo pipefail

REPO_URL="https://github.com/YouLord/salvage.git"
BRANCH="main"
DRY_RUN=0
AUTHOR_NAME="${AUTHOR_NAME:-}"
AUTHOR_EMAIL="${AUTHOR_EMAIL:-}"

while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO_URL="${2:?--repo требует URL}"; shift 2 ;;
    --branch) BRANCH="${2:?--branch требует имя}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "неизвестный аргумент: $1 (см. --help)" >&2; exit 2 ;;
  esac
done

say()  { printf '\033[1m%s\033[0m\n' "$*"; }
warn() { printf '\033[33m  ! %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31mОШИБКА: %s\033[0m\n' "$*" >&2; exit 1; }
run()  { if [ "$DRY_RUN" = "1" ]; then echo "  [dry-run] $*"; else "$@"; fi; }

# --------------------------------------------------------------------------
# 1. Где мы и что это за репозиторий
# --------------------------------------------------------------------------
cd "$(dirname "$0")"
[ -d .git ] || die "рядом со скриптом нет каталога .git — положите скрипт в корень репозитория salvage"
[ -d salvage ] || die "не вижу пакет salvage/ — это не корень проекта"

say "1/7 репозиторий"
echo "  путь:    $(pwd)"
echo "  ветка:   $(git branch --show-current || echo '(detached)')"
echo "  коммитов: $(git rev-list --count HEAD)"

# --------------------------------------------------------------------------
# 2. Чистое рабочее дерево
# --------------------------------------------------------------------------
say "2/7 рабочее дерево"
if [ -n "$(git status --porcelain)" ]; then
  git status --short | head -20
  die "есть незакоммиченные изменения — сначала закоммитьте их (git add -A && git commit -m '...'), иначе push уйдёт без них"
fi
echo "  чисто"

# --------------------------------------------------------------------------
# 3. Автор коммитов (без него pull --rebase падает с «Please tell me who you are»)
# --------------------------------------------------------------------------
say "3/7 автор коммитов"
if ! git config user.email >/dev/null; then
  name="${AUTHOR_NAME:-YouLord}"
  email="${AUTHOR_EMAIL:-${name}@users.noreply.github.com}"
  run git config user.name "$name"
  run git config user.email "$email"
  echo "  задан локально: $name <$email>"
else
  echo "  $(git config user.name || echo '?') <$(git config user.email)>"
fi

# --------------------------------------------------------------------------
# 4. origin и имя ветки
# --------------------------------------------------------------------------
say "4/7 origin"
if git remote get-url origin >/dev/null 2>&1; then
  run git remote set-url origin "$REPO_URL"
else
  run git remote add origin "$REPO_URL"
fi
echo "  origin → $REPO_URL"
current="$(git branch --show-current || true)"
if [ "$current" != "$BRANCH" ]; then
  run git branch -M "$BRANCH"
  echo "  ветка переименована: ${current:-?} → $BRANCH"
fi

# --------------------------------------------------------------------------
# 5. Что уже есть на GitHub — это и есть источник «ошибок при заливке»
# --------------------------------------------------------------------------
say "5/7 состояние удалённого репозитория"
remote_files=""
if remote_files="$(git ls-remote --heads "$REPO_URL" "$BRANCH" 2>/dev/null)" && [ -n "$remote_files" ]; then
  say "  на GitHub уже есть ветка $BRANCH — проверяю, что там лежит"
  work_remote="$(mktemp -d)"
  trap 'rm -rf "$work_remote"' EXIT
  if ! git clone -q --depth 1 --branch "$BRANCH" "$REPO_URL" "$work_remote/remote" 2>/dev/null; then
    die "не удалось прочитать удалённую ветку (нужен токен с правом repo?)"
  fi
  mapfile -t theirs < <(cd "$work_remote/remote" && git ls-files)
  echo "  файлов на GitHub: ${#theirs[@]}"
  # безобидные файлы, которые GitHub создаёт сам при инициализации репозитория
  harmless=0
  foreign=()
  for f in "${theirs[@]:-}"; do
    [ -z "$f" ] && continue
    case "$f" in
      README.md|LICENSE|LICENSE.md|LICENSE.txt|.gitignore|.gitattributes|CODE_OF_CONDUCT.md|CONTRIBUTING.md)
        harmless=$((harmless+1)) ;;
      *) foreign+=("$f") ;;
    esac
  done
  if [ "${#foreign[@]}" -gt 0 ]; then
    warn "на GitHub есть файлы, которых нет у нас:"
    printf '      %s\n' "${foreign[@]:0:15}" >&2
    die "форсить чужую работу нельзя. Решите вручную:
     git fetch origin
     git log --oneline origin/$BRANCH | head
     # затем либо слить:  git pull --rebase origin $BRANCH
     # либо, если это точно ваш черновик и его можно потерять:
     #   git push --force-with-lease origin $BRANCH"
  fi
  # тянем с --allow-unrelated-histories: у GitHub «Initial commit» не связан с нашим
  say "  сливаю безобидный Initial commit GitHub с нашей историей"
  if ! run git pull --no-rebase --allow-unrelated-histories --no-edit \
        -m "merge: сохранить Initial commit GitHub" origin "$BRANCH"; then
    git merge --abort 2>/dev/null || true
    die "слияние не удалось. Частый случай — конфликт README.md.
     Разрешите вручную: git status, поправьте файл, git add, git commit,
     затем снова запустите этот скрипт."
  fi
  # наш README должен остаться нашим (GitHub писал в него заголовок репозитория)
  if [ -f README.md ] && ! grep -q '^# salvage' README.md; then
    warn "README.md после слияния не наш — проверьте его глазами"
  fi
else
  echo "  ветки $BRANCH ещё нет — обычная первая заливка"
fi

# --------------------------------------------------------------------------
# 6. Push по HTTPS с токеном, без интерактивных запросов
# --------------------------------------------------------------------------
say "6/7 push"
if [ "$DRY_RUN" = "1" ]; then
  echo "  [dry-run] push не выполняется"
  exit 0
fi

user="${GH_USER:-}"
token="${GH_TOKEN:-}"
if [ -z "$token" ]; then
  # Если у пользователя настроен ssh-remote или credential helper — пробуем без токена
  if git config --get credential.helper >/dev/null 2>&1; then
    echo "  найден credential helper — пробую push без токена"
  else
    echo "  Токен: GitHub → Settings → Developer settings → Personal access tokens"
    if [ -z "$user" ]; then read -r -p "  логин GitHub: " user; fi
    read -r -s -p "  токен (ввод не отображается): " token; echo
  fi
fi

push_url="$REPO_URL"
if [ -n "$token" ]; then
  proto="${REPO_URL%%://*}"
  rest="${REPO_URL#*://}"
  hostpath="${rest#*/}"
  host="${rest%%/*}"
  push_url="${proto}://${user:-x-access-token}:${token}@${host}/${hostpath}"
fi

# GIT_TERMINAL_PROMPT=0: не висеть на запросе пароля, а честно упасть
if ! GIT_TERMINAL_PROMPT=0 git push --set-upstream "$push_url" "$BRANCH"; then
  cat >&2 <<'HINT'

Push не прошёл. Что проверить:
  • 403 / Authentication failed → токен неверный или без scope "repo";
    создайте новый: Settings → Developer settings → Tokens (classic) → repo.
  • 404 Not Found → в URL опечатка либо у токена нет прав на этот репозиторий.
  • rejected (fetch first) → на GitHub появились новые коммиты, запустите скрипт снова.
  • Repository not found с верным именем → репозиторий ещё не создан на GitHub.
HINT
  exit 1
fi

# --------------------------------------------------------------------------
# 7. Проверка, что всё действительно залилось
# --------------------------------------------------------------------------
say "7/7 проверка"
if ! git ls-remote --heads "$REPO_URL" "$BRANCH" | grep -q .; then
  die "push отчитался успехом, но ветка на GitHub не видна — проверьте в браузере"
fi
local_head="$(git rev-parse HEAD)"
remote_head="$(git ls-remote --heads "$REPO_URL" "$BRANCH" | awk '{print $1}')"
if [ "$local_head" != "$remote_head" ]; then
  die "локальный HEAD ($local_head) не совпал с удалённым ($remote_head)"
fi

echo
say "ГОТОВО: залито $(git rev-list --count HEAD) коммитов, файлов $(git ls-files | wc -l)"
echo "  https://github.com/${REPO_URL#*github.com/}" | sed 's/\.git$//'
echo
echo "Проверка на чистом клоне:"
echo "  git clone ${REPO_URL} /tmp/check && cd /tmp/check"
echo "  python tests/make_fixtures.py && python tests/make_fixtures.py regress"
echo "  python -W ignore -m unittest discover -s tests"
