package main

import (
	cfg "github.com/conductorone/baton-oracle-fccs/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/config"
)

func main() {
	config.Generate("oracle-fccs", cfg.Config)
}
