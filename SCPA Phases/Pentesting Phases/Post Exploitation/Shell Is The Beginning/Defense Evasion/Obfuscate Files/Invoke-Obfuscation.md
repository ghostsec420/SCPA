# Invoke-Obfuscation

## 01 - Manual

- Run powershell prompt in linux

`$ pwsh`

`PS /home/user/> cd Invoke-Obfuscation/`

- Import the powershell module

`PS /home/user/Invoke-Obfuscation> Import-Module Invoke-Obfuscation.psd1`

- Run `Invoke-Obfuscation` for a prompt

`PS /home/user/Invoke-Obfuscation> Invoke-Obfuscation`

- Set the `SCRIPTPATH` to prepare for encoding powershell scripts

`Invoke-Obfuscation> SET SCRIPTPATH /home/user/powershell_scripts/shell.ps1`

- Type `ENCODING` for encode the powershell script in various ways

`Invoke-Obfuscation> ENCODING`

- `5` as in `SecureString (AES)` then save the obfuscated powershell script that is ready to be deployed

`Invoke-Obfuscation\Encoding> 5`

- This one requires powershell version 3.0 or above

`Invoke-Obfuscation> AST`

`Invoke-Obfuscation\AST> ALL`

- Copy the obfuscated powershell script that is deployable to evade anti-viruses

`Invoke-Obfuscation\AST\All> 1`