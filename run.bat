@echo off
cls

REM if npm is installed
where npm >nul 2>nul
if %errorlevel% == 0 (
	goto :run
)

if exist node-v18.16.0-win-x64\ (
	goto :run
) else (
	goto :download_node
)

REM run client
:run
REM check for any module used by the client
if exist node_modules\inquirer\ (
	REM if modules installed, start client either using local node or installed node
	if exist node-v18.16.0-win-x64\ (
		"node-v18.16.0-win-x64/node" --no-deprecation index.js
	) else (
		node --no-deprecation index.js
	)
) else (
	REM if modules not installed, install them and then start client either using local node or installed node
	if exist node-v18.16.0-win-x64\ (
		"node-v18.16.0-win-x64/npm" i
		"node-v18.16.0-win-x64/node" --no-deprecation index.js
	) else (
		npm i
		node --no-deprecation index.js
	)
)

REM download nodejs
:download_node
REM curl node from official source
echo Setting up nodejs for Windows...
echo.
curl -o nodejs.zip https://nodejs.org/dist/v18.16.0/node-v18.16.0-win-x64.zip
tar -xvf nodejs.zip
del nodejs.zip

goto :run
