# Unreleased
- Support pyOpenSSL 20 and newer without relying on its removed PKCS#12 API.
- Verify generated XML signatures against the certificate contained in the PFX.

# 0.2
- Add FacturaeRoot signature functionality
  - New methods
    - FacturaeRoot.sign(pkcs12_cert, password) to sign a FacturaeRoot instance
    - FacturaeRoot.sign_verify(signed_root) to verify the already created signature
- Add basic signature tests with a dummy self-signed cert
- Provide Travis-CI integration to validate tests and autodeploy to Pypi on tag
- Fix Special Taxable Event Reason attribute name #5

# 0.1.0
- Forked instance from totaler/facturae repo
