# ios-acme-simulator

A quick and dirty iOS ACME client simulator to simulate and 
test `device-attest-01` challenges with [step-ca](https://github.com/smallstep/certificates/).

# Usage

```console
./ios-acme-simulator -help
Usage of ./ios-acme-simulator:
  -client-identifier string
    	The "ClientIdentifier" to use in the ACME request
  -directory string
    	The URL of the ACME directory
  -intermediate string
    	Path to the intermediate CA certificate in PEM format
  -key string
    	Path to the intermediate CA private key
  -pass string
    	Password for the intermediate CA private key
  -root string
    	Path to the root CA certificate in PEM format
  -serial string
    	The (fake) Apple serial number (default "12345")
  -udid string
    	The (fake) Apple UDID (default "device.id1")
```

Example usage:

```console
./ios-acme-simulator -directory https://127.0.0.1:8443/acme/appleacmesim/directory  -root /path/to/root.crt -intermediate /path/to/intermediate.crt -key /path/to/intermediate.key -pass password -client-identifier device.id1
```

The example uses the [step-ca](https://github.com/smallstep/certificates/) ACME directory at [https://127.0.0.1:8443/acme/appleacmesim/directory](https://127.0.0.1:8443/acme/appleacmesim/directory) to request a certificate. 
An ACME provisioner named `appleacmesim` is configured with the following settings:

```json
    {
        "type": "ACME",
        "name": "appleacmesim",
        "challenges": [
                "device-attest-01"
        ],
        "attestationFormats": [
                "apple"
        ],
        "attestationRoots": "LS0tLS1CRUdJTiBDRVJ............SUZJQ0DQVRFLS0tLS0K"
    },
```
The `attestationRoots` is the base64 encoding of the root CA certificate used to sign the attestation certificate. 

The root, intermediate, key and password are backing the fake attestation CA and used to sign the fake attestation certificate.

In the example, the `-client-identifier` flag is set to `device.id1`. 
Because the default (fake) UDID is also `device.id1`, this should result in the certificate being issued.
[step-ca](https://github.com/smallstep/certificates/) (currently) checks that either the UDID or the serial in the attestation certificate contains the same value as the `-client-identifier` flag.
If both are different, a certificate will not be issued.
This behavior may change in the future.

The utility will print some debug logs as well as the certificate (chain) details and contents.
It will also try to do another certificate request 3 seconds after the first one.

The utility will not persist the ACME account key, and will thus create a new ACME account every time it's ran.