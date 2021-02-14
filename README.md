# crtpin

`crtpin` is a tiny program to calculate public key hashes of hosts suitable for certificate pinning.

## Usage

HTTP services running [`crtpin.veehait.ch`](https://crtpin.veehait.ch).

```sh
curl https://crtpin.veehait.ch/nixos.org
```

```json
{
  "result": {
    "cert": {
      "commonName": "*.nixos.org",
      "daysUntilExpiry": 75,
      "dnsNames": [
        "*.nixos.org",
        "nixos.org"
      ],
      "issuer": "R3",
      "notValidAfter": "2021-05-01T09:02:07Z",
      "notValidBefore": "2021-01-31T09:02:07Z",
      "serialNumber": 3.20230275935086e+41
    },
    "pins": {
      "blake2s256": "GK0cgAGtf0lQVG6aoUCuok61zSrx+CBEiwTPxUIqk+k=",
      "blake2b256": "DySrABnIreLNgWcUqX8JAHkqW2XD6/Y+pSOP4wfHxYI=",
      "sha256": "zM0mIOiZmXDc57J69igPJihA6YO9DWzA28lAHpMERVw=",
      "sha384": "y+4QoCsBJ+G3fMBmaqhEe0/Iv3vmJDGzACCwGhJrYEwoLpzNwdTyVXDGe+gWfKxe",
      "sha512": "Z95m9mw1Vyz9dRmvxv7kd0SxrqnyN9LS6iQ9e+8rOJykLEsE8Q45zE/lZO7Gt1ObyPltYM2gEAKYJqOr2MsoKg=="
    },
    "request": {
      "date": "2021-02-14T12:07:29.322842686+01:00",
      "host": "nixos.org",
      "ip": "2a03:b0c0:3:e0::27e:2001",
      "port": 443,
      "nameserver": "5.9.164.112@853#dns3.digitalcourage.de"
    }
  },
  "error": null
}
```

Get a specific pin directly using [`jq`](https://github.com/stedolan/jq):

```sh
curl -s https://crtpin.veehait.ch/nixos.org | jq -r '.result.pins.sha256'
zM0mIOiZmXDc57J69igPJihA6YO9DWzA28lAHpMERVw=
```