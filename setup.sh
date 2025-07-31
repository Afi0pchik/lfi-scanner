#!/bin/bash

GREEN="\033[0;32m"
CYAN="\033[0;36m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
NC="\033[0m" # No Color

echo -e "${CYAN}=== Setting up Python virtual environment ===${NC}"

# Проверяем наличие python3
if ! command -v python3 &> /dev/null
then
    echo -e "${RED}Python3 is not installed. Please install it first.${NC}"
    exit 1
fi

# Проверяем наличие pip
if ! command -v pip3 &> /dev/null
then
    echo -e "${RED}pip3 is not installed. Installing pip3...${NC}"
    python3 -m ensurepip --upgrade || { echo -e "${RED}Failed to install pip3.${NC}"; exit 1; }
fi

# Создаем виртуальное окружение, если его нет
if [ ! -d ".venv" ]; then
    echo -e "${GREEN}Creating virtual environment in .venv...${NC}"
    python3 -m venv .venv || { echo -e "${RED}Failed to create virtual environment.${NC}"; exit 1; }
else
    echo -e "${YELLOW}Virtual environment already exists. Skipping creation.${NC}"
fi

# Активируем виртуальное окружение
source .venv/bin/activate
if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to activate virtual environment.${NC}"
    exit 1
fi
echo -e "${GREEN}Virtual environment activated.${NC}"

# Устанавливаем зависимости
if [ -f "requirements.txt" ]; then
    echo -e "${GREEN}Installing dependencies from requirements.txt...${NC}"
    pip install --upgrade pip
    pip install -r requirements.txt
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Dependencies installed successfully.${NC}"
    else
        echo -e "${RED}Failed to install some dependencies.${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}requirements.txt not found. Skipping dependencies installation.${NC}"
fi

echo -e "${CYAN}Setup complete!${NC}"
echo -e "${CYAN}To activate the virtual environment later, run:${NC} source .venv/bin/activate"
