package data

import "embed"

//go:embed bounty-data/data/*.json
var BountyFS embed.FS
