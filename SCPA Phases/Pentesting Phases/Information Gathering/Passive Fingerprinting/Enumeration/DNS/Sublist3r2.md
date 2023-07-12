# Sublist3r2

## Setup

```
$ git clone https://github.com/RoninNakomoto/Sublist3r2.git && \
python3 -m venv ~/environments/sublist3r2 && \
source ~/environments/sublist3r2/bin/activate && \
python -m pip install --upgrade pip && \
cd ~/sublist3r2/ && pip install -r requirements.txt && \
deactivate
```

## Usage

TODO: Provide more usage coverage for sublist3r2

`$ source ~/environments/sublist3r2/bin/activate`

`$ sublist3r2 -d <domain.com> -b -t 64 -o subdomains.txt`

`$ sublist3r2 -d <domain.com> -o subdomains.txt`

`$ sublist3r2 -d <domain.com> -t 20 -p 21,22,80,110,443,445,3306,3389 -o subdomains.txt`

`$ sublist3r2 -e google,yahoo,virustotal -d <domain.com> -o subdomains.txt`

## References

- [Sublist3r2](https://github.com/RoninNakomoto/Sublist3r2.git)