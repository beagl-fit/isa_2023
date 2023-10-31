#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
CIAN='\033[0;36m'
DEFAULT='\033[0m'

RIGHT=0
WRONG=0

echo -e "${CIAN}Test start:${DEFAULT}"

# Test 1
echo "Test 1: ./dns"
./dns >/dev/null 2>&1

if [ $? -eq 1 ]; then
    echo -e "${GREEN}Trying to execute file without arguments failed${DEFAULT}"
    RIGHT=$((RIGHT + 1))
else
    echo -e "${RED}Trying to execute file without arguments didn't fail${DEFAULT}"
    WRONG=$((WRONG + 1))
fi

###########################################################################
# Test 2
echo "Test 2: ./dns -s kazi.fit.vutbr.cz"
./dns -s kazi.fit.vutbr.cz >/dev/null 2>&1

if [ $? -eq 1 ]; then
    echo -e "${GREEN}Trying to execute file without address failed${DEFAULT}"
    RIGHT=$((RIGHT + 1))
else
    echo -e "${RED}Trying to execute file without address didn't fail${DEFAULT}"
    WRONG=$((WRONG + 1))
fi

###########################################################################
# Test 3
echo "Test 3: ./dns fit.vutbr.cz"
./dns fit.vutbr.cz >/dev/null 2>&1

if [ $? -eq 1 ]; then
    echo -e "${GREEN}Trying to execute file without server failed${DEFAULT}"
    RIGHT=$((RIGHT + 1))
else
    echo -e "${RED}Trying to execute file without server didn't fail${DEFAULT}"
    WRONG=$((WRONG + 1))
fi

###########################################################################
# Test 4
echo "Test 4: ./dns -s kazi.fit.vutbr.cz fit.vutbr.cz"
./dns -s kazi.fit.vutbr.cz fit.vutbr.cz >/dev/null 2>&1

if [ $? -eq 1 ]; then
    echo -e "${RED}Trying to execute file correctly failed${DEFAULT}"
    WRONG=$((WRONG + 1))
else
    echo -e "${GREEN}Trying to execute file correctly didn't fail${DEFAULT}"
    RIGHT=$((RIGHT + 1))
fi

###########################################################################
# Test 5
echo "Test 5: ./dns -s kazi.fit.vutbr.cz fit.vutbr.cz (-s kazi.fit.vutbr.cz/fit.vutbr.cz)"
./dns -s kazi.fit.vutbr.cz fit.vutbr.cz fit.vutbr.cz >/dev/null 2>&1

T_RESULT=$?
./dns -s kazi.fit.vutbr.cz fit.vutbr.cz -s kazi.fit.vutbr.cz >/dev/null 2>&1
T2_RESULT=$?

if [ $T_RESULT -eq 0 ] || [ $T2_RESULT -eq 0 ]; then
    echo -e "${RED}Trying to execute file with 2 servers or 2 addresses didn't fail${DEFAULT}"
    WRONG=$((WRONG + 1))
else
    echo -e "${GREEN}Trying to execute file with 2 servers or 2 addresses failed${DEFAULT}"
    RIGHT=$((RIGHT + 1))
fi

###########################################################################
# Test 6
echo "Test 6: ./dns -p 53 -6 -r -s kazi.fit.vutbr.cz fit.vutbr.cz"
./dns  -p 53 -6 -r -s kazi.fit.vutbr.cz fit.vutbr.cz >/dev/null 2>&1

if [ $? -eq 1 ]; then
    echo -e "${RED}Trying to execute file with non-required arguments failed${DEFAULT}"
    WRONG=$((WRONG + 1))
else
    echo -e "${GREEN}Trying to execute file with non-required arguments didn't fail${DEFAULT}"
    RIGHT=$((RIGHT + 1))
fi

###########################################################################
# Test 7
echo "Test 7: ./dns -s 147.229.8.12 fit.vutbr.cz"
./dns -s 147.229.8.12 fit.vutbr.cz >/dev/null 2>&1

if [ $? -eq 1 ]; then
    echo -e "${RED}Trying to execute file with server given as IP address failed${DEFAULT}"
    WRONG=$((WRONG + 1))
else
    echo -e "${GREEN}Trying to execute file server given as IP address didn't fail${DEFAULT}"
    RIGHT=$((RIGHT + 1))
fi

###########################################################################
# Test 8
echo "Test 8: ./dns -s 147.229.8.12.12.12 fit.vutbr.cz"
./dns -s 147.229.8.12.12.12 fit.vutbr.cz >/dev/null 2>&1

if [ $? -eq 1 ]; then
    echo -e "${GREEN}Trying to execute file server given as wrong IP address failed${DEFAULT}"
    RIGHT=$((RIGHT + 1))
else
    echo -e "${RED}Trying to execute file with server given as wrong IP address didn't fail${DEFAULT}"
    WRONG=$((WRONG + 1))
fi

###########################################################################
# Test 9
echo "Test 9: ./dns -s too_long_domain fit.vutbr.cz"
./dns -s too_long_domaintoo_long_domaintoo_long_domaintoo_long_domaintoo_long_domain.cz fit.vutbr.cz >/dev/null 2>&1
T_RESULT=$?

./dns -s too_long_domaintoo_long_domain.too_long_domaintoo_long_domain.too_long_domaintoo_long_domain.too_long_domaintoo_long_domain.too_long_domaintoo_long_domain.cz kazi.fit.vutbr.cz >/dev/null 2>&1
T2_RESULT=$?

if [ $T_RESULT -eq 0 ] || [ $T2_RESULT -eq 0 ]; then
    echo -e "${RED}Trying to execute file with server containing too many domains or a too long domain didn't fail${DEFAULT}"
    WRONG=$((WRONG + 1))
else
    echo -e "${GREEN}Trying to execute file with server containing too many domains or a too long domain failed${DEFAULT}"
    RIGHT=$((RIGHT + 1))
fi

###########################################################################
# Test 10
echo -e "Test 10: ./dns -s some.completely.unknown.and.non-existent.server.cz fit.vutbr.cz\t${CIAN}Will take 30 sec to timeout${DEFAULT}"
./dns -s some.completely.unknown.and.non-existent.server.cz fit.vutbr.cz >/dev/null 2>&1

if [ $? -eq 1 ]; then
    echo -e "${GREEN}Trying to execute file with non-existent server failed${DEFAULT}"
    RIGHT=$((RIGHT + 1))
else
    echo -e "${RED}Trying to execute file with non-existent server didn't fail${DEFAULT}"
    WRONG=$((WRONG + 1))
fi

echo -e "Summary:\n${GREEN}Tests passed: ${RIGHT}\t\t${RED}Tests failed:${WRONG}${DEFAULT}"
