@echo off
cmake --preset win-amd64 --fresh
cmake --build --preset win-amd64-relwithdebinfo --target install
pause