/** Names for the object identifiers the PKI tools display. */

export const OID = {
  rsaEncryption: '1.2.840.113549.1.1.1',
  rsaPss: '1.2.840.113549.1.1.10',
  ecPublicKey: '1.2.840.10045.2.1',
  dsa: '1.2.840.10040.4.1',
  ed25519: '1.3.101.112',
  ed448: '1.3.101.113',
  x25519: '1.3.101.110',
  x448: '1.3.101.111',
  sha1: '1.3.14.3.2.26',
  p256: '1.2.840.10045.3.1.7',
  p384: '1.3.132.0.34',
  p521: '1.3.132.0.35',
  // extensions
  subjectKeyIdentifier: '2.5.29.14',
  keyUsage: '2.5.29.15',
  subjectAltName: '2.5.29.17',
  issuerAltName: '2.5.29.18',
  basicConstraints: '2.5.29.19',
  crlNumber: '2.5.29.20',
  crlReason: '2.5.29.21',
  invalidityDate: '2.5.29.24',
  deltaCrlIndicator: '2.5.29.27',
  issuingDistributionPoint: '2.5.29.28',
  certificateIssuer: '2.5.29.29',
  nameConstraints: '2.5.29.30',
  crlDistributionPoints: '2.5.29.31',
  certificatePolicies: '2.5.29.32',
  policyMappings: '2.5.29.33',
  authorityKeyIdentifier: '2.5.29.35',
  policyConstraints: '2.5.29.36',
  extKeyUsage: '2.5.29.37',
  freshestCrl: '2.5.29.46',
  inhibitAnyPolicy: '2.5.29.54',
  authorityInfoAccess: '1.3.6.1.5.5.7.1.1',
  subjectInfoAccess: '1.3.6.1.5.5.7.1.11',
  tlsFeature: '1.3.6.1.5.5.7.1.24',
  sctList: '1.3.6.1.4.1.11129.2.4.2',
  ctPoison: '1.3.6.1.4.1.11129.2.4.3',
  ocspNoCheck: '1.3.6.1.5.5.7.48.1.5',
  // access methods
  ocsp: '1.3.6.1.5.5.7.48.1',
  caIssuers: '1.3.6.1.5.5.7.48.2',
  // EKU
  serverAuth: '1.3.6.1.5.5.7.3.1',
  clientAuth: '1.3.6.1.5.5.7.3.2',
  anyEku: '2.5.29.37.0',
  // attributes
  commonName: '2.5.4.3',
  emailAddress: '1.2.840.113549.1.9.1',
  challengePassword: '1.2.840.113549.1.9.7',
  extensionRequest: '1.2.840.113549.1.9.14',
  // CMS
  signedData: '1.2.840.113549.1.7.2',
} as const

export const SIGNATURE_ALGS: Record<string, { name: string; hash?: string; weak?: 'md' | 'sha1' }> = {
  '1.2.840.113549.1.1.2': { name: 'md2WithRSAEncryption', hash: 'MD2', weak: 'md' },
  '1.2.840.113549.1.1.3': { name: 'md4WithRSAEncryption', hash: 'MD4', weak: 'md' },
  '1.2.840.113549.1.1.4': { name: 'md5WithRSAEncryption', hash: 'MD5', weak: 'md' },
  '1.2.840.113549.1.1.5': { name: 'sha1WithRSAEncryption', hash: 'SHA-1', weak: 'sha1' },
  '1.3.14.3.2.29': { name: 'sha1WithRSASignature (OIW)', hash: 'SHA-1', weak: 'sha1' },
  '1.2.840.113549.1.1.10': { name: 'RSASSA-PSS' },
  '1.2.840.113549.1.1.11': { name: 'sha256WithRSAEncryption', hash: 'SHA-256' },
  '1.2.840.113549.1.1.12': { name: 'sha384WithRSAEncryption', hash: 'SHA-384' },
  '1.2.840.113549.1.1.13': { name: 'sha512WithRSAEncryption', hash: 'SHA-512' },
  '1.2.840.113549.1.1.14': { name: 'sha224WithRSAEncryption', hash: 'SHA-224' },
  '1.2.840.10045.4.1': { name: 'ecdsa-with-SHA1', hash: 'SHA-1', weak: 'sha1' },
  '1.2.840.10045.4.3.1': { name: 'ecdsa-with-SHA224', hash: 'SHA-224' },
  '1.2.840.10045.4.3.2': { name: 'ecdsa-with-SHA256', hash: 'SHA-256' },
  '1.2.840.10045.4.3.3': { name: 'ecdsa-with-SHA384', hash: 'SHA-384' },
  '1.2.840.10045.4.3.4': { name: 'ecdsa-with-SHA512', hash: 'SHA-512' },
  '1.2.840.10040.4.3': { name: 'dsa-with-SHA1', hash: 'SHA-1', weak: 'sha1' },
  '2.16.840.1.101.3.4.3.2': { name: 'dsa-with-SHA256', hash: 'SHA-256' },
  '1.3.101.112': { name: 'Ed25519' },
  '1.3.101.113': { name: 'Ed448' },
  '2.16.840.1.101.3.4.3.17': { name: 'ML-DSA-44' },
  '2.16.840.1.101.3.4.3.18': { name: 'ML-DSA-65' },
  '2.16.840.1.101.3.4.3.19': { name: 'ML-DSA-87' },
}

export const KEY_ALGS: Record<string, string> = {
  '1.2.840.113549.1.1.1': 'RSA',
  '1.2.840.113549.1.1.10': 'RSA-PSS',
  '1.2.840.10045.2.1': 'EC',
  '1.2.840.10040.4.1': 'DSA',
  '1.3.101.110': 'X25519',
  '1.3.101.111': 'X448',
  '1.3.101.112': 'Ed25519',
  '1.3.101.113': 'Ed448',
  '2.16.840.1.101.3.4.3.17': 'ML-DSA-44',
  '2.16.840.1.101.3.4.3.18': 'ML-DSA-65',
  '2.16.840.1.101.3.4.3.19': 'ML-DSA-87',
}

export const CURVES: Record<string, string> = {
  '1.2.840.10045.3.1.7': 'P-256',
  '1.3.132.0.34': 'P-384',
  '1.3.132.0.35': 'P-521',
  '1.2.840.10045.3.1.1': 'P-192',
  '1.3.132.0.33': 'P-224',
  '1.3.132.0.10': 'secp256k1',
  '1.3.36.3.3.2.8.1.1.7': 'brainpoolP256r1',
  '1.3.36.3.3.2.8.1.1.11': 'brainpoolP384r1',
  '1.3.36.3.3.2.8.1.1.13': 'brainpoolP512r1',
}

export const EXTENSIONS: Record<string, string> = {
  '2.5.29.9': 'Subject Directory Attributes',
  '2.5.29.14': 'Subject Key Identifier',
  '2.5.29.15': 'Key Usage',
  '2.5.29.16': 'Private Key Usage Period',
  '2.5.29.17': 'Subject Alternative Name',
  '2.5.29.18': 'Issuer Alternative Name',
  '2.5.29.19': 'Basic Constraints',
  '2.5.29.20': 'CRL Number',
  '2.5.29.21': 'CRL Reason Code',
  '2.5.29.24': 'Invalidity Date',
  '2.5.29.27': 'Delta CRL Indicator',
  '2.5.29.28': 'Issuing Distribution Point',
  '2.5.29.29': 'Certificate Issuer',
  '2.5.29.30': 'Name Constraints',
  '2.5.29.31': 'CRL Distribution Points',
  '2.5.29.32': 'Certificate Policies',
  '2.5.29.33': 'Policy Mappings',
  '2.5.29.35': 'Authority Key Identifier',
  '2.5.29.36': 'Policy Constraints',
  '2.5.29.37': 'Extended Key Usage',
  '2.5.29.46': 'Freshest CRL',
  '2.5.29.54': 'Inhibit anyPolicy',
  '1.3.6.1.5.5.7.1.1': 'Authority Information Access',
  '1.3.6.1.5.5.7.1.3': 'Qualified Certificate Statements',
  '1.3.6.1.5.5.7.1.11': 'Subject Information Access',
  '1.3.6.1.5.5.7.1.24': 'TLS Feature (OCSP Must-Staple)',
  '1.3.6.1.4.1.11129.2.4.2': 'CT Signed Certificate Timestamps',
  '1.3.6.1.4.1.11129.2.4.3': 'CT Precertificate Poison',
  '1.3.6.1.5.5.7.48.1.5': 'OCSP No Check',
  '1.3.6.1.4.1.311.20.2': 'Microsoft Certificate Template Name',
  '1.3.6.1.4.1.311.21.1': 'Microsoft CA Version',
  '1.3.6.1.4.1.311.21.2': 'Microsoft Previous CA Cert Hash',
  '1.3.6.1.4.1.311.21.7': 'Microsoft Certificate Template',
  '1.3.6.1.4.1.311.21.10': 'Microsoft Application Policies',
  '1.3.6.1.4.1.311.25.2': 'Microsoft NTDS CA Security',
  '2.16.840.1.113730.1.1': 'Netscape Cert Type',
  '2.16.840.1.113730.1.13': 'Netscape Comment',
}

/**
 * Extensions that RFC 5280 / common verifiers process. A critical extension outside this set will make most
 * relying parties reject the certificate.
 */
export const PROCESSABLE_EXTENSIONS = new Set([
  '2.5.29.14',
  '2.5.29.15',
  '2.5.29.17',
  '2.5.29.18',
  '2.5.29.19',
  '2.5.29.30',
  '2.5.29.31',
  '2.5.29.32',
  '2.5.29.33',
  '2.5.29.35',
  '2.5.29.36',
  '2.5.29.37',
  '2.5.29.46',
  '2.5.29.54',
  '1.3.6.1.5.5.7.1.1',
  '1.3.6.1.5.5.7.1.11',
  '1.3.6.1.5.5.7.1.24',
  '1.3.6.1.5.5.7.48.1.5',
])

export const EKUS: Record<string, string> = {
  '1.3.6.1.5.5.7.3.1': 'TLS Web Server Authentication (serverAuth)',
  '1.3.6.1.5.5.7.3.2': 'TLS Web Client Authentication (clientAuth)',
  '1.3.6.1.5.5.7.3.3': 'Code Signing',
  '1.3.6.1.5.5.7.3.4': 'E-mail Protection (S/MIME)',
  '1.3.6.1.5.5.7.3.5': 'IPsec End System',
  '1.3.6.1.5.5.7.3.6': 'IPsec Tunnel',
  '1.3.6.1.5.5.7.3.7': 'IPsec User',
  '1.3.6.1.5.5.7.3.8': 'Time Stamping',
  '1.3.6.1.5.5.7.3.9': 'OCSP Signing',
  '1.3.6.1.5.5.7.3.17': 'IPsec IKE',
  '1.3.6.1.5.5.7.3.36': 'Document Signing (RFC 9336)',
  '2.5.29.37.0': 'Any Extended Key Usage',
  '1.3.6.1.5.2.3.5': 'Kerberos KDC',
  '1.3.6.1.4.1.311.20.2.2': 'Microsoft Smart Card Logon',
  '1.3.6.1.4.1.311.10.3.3': 'Microsoft Server Gated Crypto',
  '1.3.6.1.4.1.311.10.3.4': 'Microsoft Encrypting File System',
  '1.3.6.1.4.1.311.10.3.12': 'Microsoft Document Signing',
  '1.3.6.1.4.1.311.10.3.13': 'Microsoft Lifetime Signing',
  '2.16.840.1.113730.4.1': 'Netscape Server Gated Crypto',
  '1.3.6.1.4.1.11129.2.4.4': 'Certificate Transparency precertificate signing',
}

/** Certificate policy OIDs: CA/Browser Forum reserved policy identifiers and a few well-known ones. */
export const POLICIES: Record<string, string> = {
  '2.5.29.32.0': 'anyPolicy',
  '2.23.140.1.1': 'CA/B Forum Extended Validation (EV) TLS',
  '2.23.140.1.2.1': 'CA/B Forum Domain Validated (DV) TLS',
  '2.23.140.1.2.2': 'CA/B Forum Organization Validated (OV) TLS',
  '2.23.140.1.2.3': 'CA/B Forum Individual Validated (IV) TLS',
  '2.23.140.1.3': 'CA/B Forum EV Code Signing',
  '2.23.140.1.4.1': 'CA/B Forum Code Signing (non-EV)',
  '2.23.140.1.4.2': 'CA/B Forum Code Signing timestamping',
  '2.23.140.1.5.1.1': 'CA/B Forum S/MIME Mailbox-validated (legacy)',
  '2.23.140.1.5.1.2': 'CA/B Forum S/MIME Mailbox-validated (multipurpose)',
  '2.23.140.1.5.1.3': 'CA/B Forum S/MIME Mailbox-validated (strict)',
  '2.23.140.1.5.2.1': 'CA/B Forum S/MIME Organization-validated (legacy)',
  '2.23.140.1.5.2.2': 'CA/B Forum S/MIME Organization-validated (multipurpose)',
  '2.23.140.1.5.2.3': 'CA/B Forum S/MIME Organization-validated (strict)',
  '2.23.140.1.5.3.1': 'CA/B Forum S/MIME Sponsor-validated (legacy)',
  '2.23.140.1.5.3.2': 'CA/B Forum S/MIME Sponsor-validated (multipurpose)',
  '2.23.140.1.5.3.3': 'CA/B Forum S/MIME Sponsor-validated (strict)',
  '2.23.140.1.5.4.1': 'CA/B Forum S/MIME Individual-validated (legacy)',
  '2.23.140.1.5.4.2': 'CA/B Forum S/MIME Individual-validated (multipurpose)',
  '2.23.140.1.5.4.3': 'CA/B Forum S/MIME Individual-validated (strict)',
  '1.3.6.1.4.1.44947.1.1.1': 'ISRG Domain Validated (Let’s Encrypt, legacy)',
  '1.3.6.1.5.5.7.2.1': 'CPS pointer qualifier',
  '1.3.6.1.5.5.7.2.2': 'User notice qualifier',
}

export const ACCESS_METHODS: Record<string, string> = {
  '1.3.6.1.5.5.7.48.1': 'OCSP',
  '1.3.6.1.5.5.7.48.2': 'CA Issuers',
  '1.3.6.1.5.5.7.48.3': 'Time Stamping',
  '1.3.6.1.5.5.7.48.5': 'CA Repository',
}

/** Distinguished-name attribute types: short label (OpenSSL style) and long name. */
export const NAME_ATTRS: Record<string, { short: string; long: string }> = {
  '2.5.4.3': { short: 'CN', long: 'Common Name' },
  '2.5.4.4': { short: 'SN', long: 'Surname' },
  '2.5.4.5': { short: 'serialNumber', long: 'Serial Number' },
  '2.5.4.6': { short: 'C', long: 'Country' },
  '2.5.4.7': { short: 'L', long: 'Locality' },
  '2.5.4.8': { short: 'ST', long: 'State / Province' },
  '2.5.4.9': { short: 'street', long: 'Street' },
  '2.5.4.10': { short: 'O', long: 'Organization' },
  '2.5.4.11': { short: 'OU', long: 'Organizational Unit' },
  '2.5.4.12': { short: 'title', long: 'Title' },
  '2.5.4.15': { short: 'businessCategory', long: 'Business Category' },
  '2.5.4.17': { short: 'postalCode', long: 'Postal Code' },
  '2.5.4.42': { short: 'GN', long: 'Given Name' },
  '2.5.4.43': { short: 'initials', long: 'Initials' },
  '2.5.4.46': { short: 'dnQualifier', long: 'DN Qualifier' },
  '2.5.4.65': { short: 'pseudonym', long: 'Pseudonym' },
  '2.5.4.97': { short: 'organizationIdentifier', long: 'Organization Identifier' },
  '1.2.840.113549.1.9.1': { short: 'emailAddress', long: 'E-mail Address' },
  '0.9.2342.19200300.100.1.1': { short: 'UID', long: 'User ID' },
  '0.9.2342.19200300.100.1.25': { short: 'DC', long: 'Domain Component' },
  '1.3.6.1.4.1.311.60.2.1.1': { short: 'jurisdictionL', long: 'Jurisdiction Locality' },
  '1.3.6.1.4.1.311.60.2.1.2': { short: 'jurisdictionST', long: 'Jurisdiction State' },
  '1.3.6.1.4.1.311.60.2.1.3': { short: 'jurisdictionC', long: 'Jurisdiction Country' },
}

const MISC: Record<string, string> = {
  '1.3.14.3.2.26': 'sha1',
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
  '1.2.840.113549.2.5': 'md5',
  '1.2.840.113549.1.1.8': 'mgf1',
  '1.2.840.113549.1.7.1': 'data',
  '1.2.840.113549.1.7.2': 'signedData',
  '1.2.840.113549.1.9.7': 'challengePassword',
  '1.2.840.113549.1.9.14': 'extensionRequest',
  '1.2.840.113549.1.9.3': 'contentType',
  '1.2.840.113549.1.9.4': 'messageDigest',
  '1.2.840.113549.1.9.5': 'signingTime',
  '1.3.6.1.5.5.7.48.1.1': 'id-pkix-ocsp-basic',
  '1.3.6.1.5.5.7.48.1.2': 'id-pkix-ocsp-nonce',
}

/** Best-effort friendly name for any OID. */
export function oidName(oid: string): string | undefined {
  return (
    SIGNATURE_ALGS[oid]?.name ??
    KEY_ALGS[oid] ??
    CURVES[oid] ??
    EXTENSIONS[oid] ??
    EKUS[oid] ??
    POLICIES[oid] ??
    ACCESS_METHODS[oid] ??
    NAME_ATTRS[oid]?.long ??
    MISC[oid]
  )
}

export const CRL_REASONS: Record<number, string> = {
  0: 'unspecified',
  1: 'keyCompromise',
  2: 'cACompromise',
  3: 'affiliationChanged',
  4: 'superseded',
  5: 'cessationOfOperation',
  6: 'certificateHold',
  8: 'removeFromCRL',
  9: 'privilegeWithdrawn',
  10: 'aACompromise',
}
