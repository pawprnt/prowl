{ config, ... }:

{
  environment.persistence."/persist/home" = {
    users.prowl = {
      directories = [
        ".config/prowl"
        ".ssh"
        ".local"
        ".cache"
        "Documents"
        "Downloads"
      ];
      files = [
        ".bash_history"
      ];
    };
  };
}
