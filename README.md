# Yet another OpenSSL GOST provider

## Description

Implementation of GOST cryptography provided as an OpenSSL 3.x provider.

## Dependencies

### Build environment

* conan (minimum 2.6.0)
* CMake (minimum 3.18)

### Base dependencies

* OpenSSL (minimum 3.0.9)

### Test dependencies

* GTest (minimum 1.15.0)

## Build steps

1. Download and prepare dependencies (from project root directory):
 
```bash
$ conan install . --output-folder build
```
