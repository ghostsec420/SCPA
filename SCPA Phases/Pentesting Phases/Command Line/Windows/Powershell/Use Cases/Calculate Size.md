# Calculate the size of the data

`PS C:\> Get-ChildItem -Path \\<IP>\C$\path\to\directory -Recurse -File | Measure-Object -Sum Length | Select-Object Count, Sum`

`PS C:\> Get-ChildItem -Path C:\path\to\directory -Recurse -File | Measure-Object -Sum Length | Select-Object Count, Sum`