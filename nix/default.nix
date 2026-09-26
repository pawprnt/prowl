{ lib
, buildGoModule
, fetchFromGitHub
}:

buildGoModule {
  pname = "prowl";
  version = "1.0.0";
  vendorHash = null;

  src = fetchFromGitHub {
    owner = "pawprnt";
    repo = "prowl";
    rev = "master";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };

  ldflags = [
    "-s" "-w"
    "-X" "main.version=1.0.0"
  ];

  meta = with lib; {
    description = "Comprehensive security research CLI tool with 175+ commands and 42+ scanner modules";
    homepage = "https://github.com/pawprnt/prowl";
    license = licenses.mit;
    mainProgram = "prowl";
  };
}
