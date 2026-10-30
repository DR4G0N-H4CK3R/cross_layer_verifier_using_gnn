@echo off
call .venv\Scripts\activate
python simulator_main.py --scenario %1
