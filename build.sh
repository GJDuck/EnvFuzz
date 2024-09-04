#!/bin/bash
#
# Copyright (C) National University of Singapore
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

if [ -t 1 ]
then
    RED="\033[31m"
    GREEN="\033[32m"
    YELLOW="\033[33m"
    BOLD="\033[1m"
    OFF="\033[0m"
else
    RED=
    GREEN=
    YELLOW=
    BOLD=
    OFF=
fi

set -e

VERSION=bde56202995716542b9ab6661d8f7f19b491d338

# STEP (1): install e9patch if necessary:
if [ "`readlink e9patch`" != "e9patch-$VERSION/e9patch" ]
then
    if [ ! -f e9patch-$VERSION.zip ]
    then
        echo -e "${GREEN}$0${OFF}: downloading e9patch-$VERSION.zip..."
        wget -O e9patch-$VERSION.zip \
            https://github.com/GJDuck/e9patch/archive/$VERSION.zip
    fi

    echo -e "${GREEN}$0${OFF}: extracting e9patch-$VERSION.zip..."
    unzip e9patch-$VERSION.zip

    echo -e "${GREEN}$0${OFF}: building e9patch..."
    cd e9patch-$VERSION
    ./build.sh
    cd ..
    ln -f -s e9patch-$VERSION/e9patch
    ln -f -s e9patch-$VERSION/e9tool
    ln -f -s e9patch-$VERSION/e9compile.sh
    ln -f -s e9patch-$VERSION/examples/stdlib.c
    ln -f -s e9patch-$VERSION/src/e9tool/e9plugin.h
    ln -f -s e9patch-$VERSION/src/e9tool/e9tool.h
    echo -e "${GREEN}$0${OFF}: e9patch has been built..."
else
    echo -e "${GREEN}$0${OFF}: using existing e9patch..."
fi

# STEP (2): build the hook code:
echo -e "${GREEN}$0${OFF}: building hook ($HOOK)..."
if [ "$LIBC" = "" ]
then
    LIBC="$(g++ --print-file-name=libc.so.6)"
fi
./e9compile.sh rr_main.cpp -std=c++11 -O2 -I "$PWD" 
g++ rr_main.o -o rr_main -pie -nostdlib -Wl,-z -Wl,max-page-size=4096 \
    -Wl,-z -Wl,norelro -Wl,-z -Wl,stack-size=0 -Wl,--export-dynamic -Wl,--entry=0x0

# STEP (3): patch libc:
echo -e "${GREEN}$0${OFF}: patching libc ($LIBC)..."
mkdir -p lib/
echo "./e9tool -M 'asm=\"syscall\"' -P 'replace entry(state)@rr_main' "$LIBC" -o "lib/libc.so.6""
./e9tool -CFR \
    -M  'asm="syscall"' \
    -P 'replace entry(state)@rr_main' \
    -M 'asm="rdtsc"' \
    -P 'replace rdtsc_hook(state)@rr_main' \
    -M 'asm="rdtscp"' \
    -P 'replace rdtscp_hook(state)@rr_main' \
    -M 'addr=&"abort"' \
    -P 'replace abort_hook()@rr_main' \
    "$LIBC" -o "lib/libc.so.6" | tee "build.log"

# STEP (4): compile env-fuzz:
echo -e "${GREEN}$0${OFF}: building env-fuzz..."
make env-fuzz

# STEP (5): compile extra objects
echo -e "${GREEN}$0${OFF}: building rrCovPlugin.so..."
make rrCovPlugin.so
echo -e "${GREEN}$0${OFF}: building rezzan.so..."
make rezzan

echo -e "${GREEN}$0${OFF}: done!"
echo

echo -e "${YELLOW} _____            _____              "
echo -e "| ____|_ ____   _|  ___|   _ ________"
echo -e "|  _| | '_ \ \ / / |_ | | | |_  /_  /"
echo -e "| |___| | | \ V /|  _|| |_| |/ / / / "
echo -e "|_____|_| |_|\_/ |_|   \__,_/___/___|${OFF}"

echo
echo "To use, run the following command:"
echo
echo "    env-fuzz (record|replay|fuzz) [OPTION] -- PROGRAM [ARG ...]"
echo

