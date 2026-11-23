@echo off
setlocal enabledelayedexpansion
title salvage - push to GitHub
set "GIT_TERMINAL_PROMPT=0"

echo.
echo ============================================================
echo   salvage - push project to GitHub
echo   repo: https://github.com/YouLord/salvage
echo ============================================================
echo.

where git >nul 2>nul
if errorlevel 1 goto :no_git

git --version >nul 2>nul

REM --- project dir = directory of this bat ---
set "PROJECT_DIR=%~dp0"
if "%PROJECT_DIR:~-1%"=="\" set "PROJECT_DIR=%PROJECT_DIR:~0,-1%"
cd /d "%PROJECT_DIR%"
if errorlevel 1 goto :no_dir

if not exist "salvage\__init__.py" goto :not_project
if not exist "pyproject.toml" goto :not_project
echo [INFO] project dir: %PROJECT_DIR%

if not exist ".git" (
    echo [INFO] .git not found - initializing
    git init -q
    git branch -M main
)

REM keep line endings as committed (relevant for Windows checkouts)
git config core.autocrlf false

REM --- commit identity: without it commit/merge fails ---
git config user.email >nul 2>nul
if errorlevel 1 (
    git config user.name "YouLord"
    git config user.email "YouLord@users.noreply.github.com"
    echo [INFO] identity set: YouLord
)

for /f "tokens=*" %%b in ('git rev-parse --abbrev-ref HEAD') do set "BR=%%b"
if /I not "!BR!"=="main" (
    echo [INFO] renaming branch !BR! to main
    git branch -M main
)

git remote get-url origin >nul 2>nul
if errorlevel 1 (
    git remote add origin https://github.com/YouLord/salvage.git
) else (
    git remote set-url origin https://github.com/YouLord/salvage.git
)
echo [INFO] origin configured

REM --- STEP 1: stage everything ---
echo.
echo [STEP 1] staging files
git add -A
set /a FILE_COUNT=0
for /f %%I in ('git diff --cached --name-only 2^>nul ^| find /c /v ""') do set "FILE_COUNT=%%I"
echo [INFO] staged files: !FILE_COUNT!
if "!FILE_COUNT!"=="0" goto :after_commit

REM --- STEP 2: commit ---
echo.
echo [STEP 2] commit
git commit -q -m "salvage: full project - 7 engines, reports, web console, tests"
if errorlevel 1 goto :commit_failed
echo [INFO] committed
:after_commit

REM --- STEP 3: what is already on GitHub ---
echo.
echo [STEP 3] remote state
set "REMOTE_HEAD="
for /f "tokens=1" %%h in ('git ls-remote --heads https://github.com/YouLord/salvage.git main 2^>nul') do set "REMOTE_HEAD=%%h"
if "!REMOTE_HEAD!"=="" goto :push
echo [INFO] branch main already exists on GitHub
git fetch -q origin main
if errorlevel 1 goto :push
git merge --allow-unrelated-histories -X ours --no-edit -m "merge: keep GitHub initial commit" origin/main >nul 2>nul
if errorlevel 1 (
    echo [WARN] merge failed - will try push anyway
) else (
    echo [INFO] merged, our README stays ours
)

REM --- STEP 4: push ---
:push
echo.
echo [STEP 4] pushing to GitHub
git push -u origin main
if not errorlevel 1 goto :verify

echo.
echo [WARN] push failed - probably a token is required
set "GH_TOKEN="
set /p "GH_TOKEN=GitHub token, or press Enter to cancel: "
if "!GH_TOKEN!"=="" goto :cancelled
git push https://YouLord:!GH_TOKEN!@github.com/YouLord/salvage.git main
set "PUSH_RC=%ERRORLEVEL%"
set "GH_TOKEN="
if not "%PUSH_RC%"=="0" goto :push_failed

REM --- STEP 5: verify ---
:verify
echo.
echo [STEP 5] verifying
git fetch -q origin main >nul 2>nul
set "LOCAL_HEAD="
set "REMOTE_HEAD2="
for /f "tokens=*" %%l in ('git rev-parse HEAD 2^>nul') do set "LOCAL_HEAD=%%l"
for /f "tokens=*" %%l in ('git rev-parse origin/main 2^>nul') do set "REMOTE_HEAD2=%%l"
echo [INFO] local HEAD:  !LOCAL_HEAD!
echo [INFO] remote HEAD: !REMOTE_HEAD2!
if /I "!LOCAL_HEAD!"=="!REMOTE_HEAD2!" goto :done
echo [WARN] HEAD mismatch - check the repository manually
goto :done

:done
echo.
echo ============================================================
echo   DONE - https://github.com/YouLord/salvage
echo ============================================================
echo.
echo Verify on another machine:
echo   git clone https://github.com/YouLord/salvage.git
echo   cd salvage
echo   python tests\make_fixtures.py
echo   python tests\make_fixtures.py regress
echo   python -m unittest discover -s tests
echo.
pause
goto :eof

:no_git
echo [ERROR] Git not found in PATH.
echo         Install: https://git-scm.com/download/win
pause
exit /b 1

:no_dir
echo [ERROR] Cannot enter project directory: %PROJECT_DIR%
pause
exit /b 1

:not_project
echo [ERROR] Not the salvage project root.
echo         Current dir: %PROJECT_DIR%
echo         Put this bat next to README.md, in the project root.
pause
exit /b 1

:commit_failed
echo [ERROR] Commit failed.
pause
exit /b 1

:cancelled
set "GH_TOKEN="
echo [ERROR] Cancelled.
pause
exit /b 1

:push_failed
echo.
echo [ERROR] Push failed. Check:
echo         - token is valid and has scope "repo";
echo         - repo https://github.com/YouLord/salvage exists;
echo         - if GitHub has foreign files: git push --force-with-lease origin main
pause
exit /b 1
