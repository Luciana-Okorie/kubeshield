package main

// Registers the "pgx" database/sql driver. Enabled with `-tags pgx` once the
// dependency exists: go get github.com/jackc/pgx/v5 && go mod tidy
import _ "github.com/jackc/pgx/v5/stdlib"
