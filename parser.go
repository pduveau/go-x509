// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	asn1 "github.com/pduveau/go-asn1"
	"github.com/pduveau/go-x509/pkix"
)

// isPrintable reports whether the given b is in the ASN.1 PrintableString set.
// This is a simplified version of encoding/asn1.isPrintable.
func isPrintable(b byte) bool {
	return 'a' <= b && b <= 'z' ||
		'A' <= b && b <= 'Z' ||
		'0' <= b && b <= '9' ||
		'\'' <= b && b <= ')' ||
		'+' <= b && b <= '/' ||
		b == ' ' ||
		b == ':' ||
		b == '=' ||
		b == '?' ||
		// This is technically not allowed in a PrintableString.
		// However, x509 certificates with wildcard strings don't
		// always use the correct string type so we permit it.
		b == '*' ||
		// This is not technically allowed either. However, not
		// only is it relatively common, but there are also a
		// handful of CA certificates that contain it. At least
		// one of which will not expire until 2027.
		b == '&'
}

// parseASN1String parses the ASN.1 string types T61String, PrintableString,
// UTF8String, BMPString, IA5String, and NumericString. This is mostly copied
// from the respective encoding/asn1.parse... methods, rather than just
// increasing the API surface of that package.
func parseASN1String(tag pkix.Tag, value []byte) (any, error) {
	switch tag {
	case pkix.T61String:
		// T.61 is a defunct ITU 8-bit character encoding which preceded Unicode.
		// T.61 uses a code page layout that _almost_ exactly maps to the code
		// page layout of the ISO 8859-1 (Latin-1) character encoding, with the
		// exception that a number of characters in Latin-1 are not present
		// in T.61.
		//
		// Instead of mapping which characters are present in Latin-1 but not T.61,
		// we just treat these strings as being encoded using Latin-1. This matches
		// what most of the world does, including BoringSSL.
		buf := make([]byte, 0, len(value))
		for _, v := range value {
			// All the 1-byte UTF-8 runes map 1-1 with Latin-1.
			buf = utf8.AppendRune(buf, rune(v))
		}
		return asn1.T61String(buf), nil
	case pkix.PrintableString:
		for _, b := range value {
			if !isPrintable(b) {
				return "", errors.New("invalid PrintableString")
			}
		}
		return string(value), nil
	case pkix.UTF8String:
		if !utf8.Valid(value) {
			return "", errors.New("invalid UTF-8 string")
		}
		return asn1.UTF8String(value), nil
	case pkix.Tag(asn1.TagBMPString):
		// BMPString uses the defunct UCS-2 16-bit character encoding, which
		// covers the Basic Multilingual Plane (BMP). UTF-16 was an extension of
		// UCS-2, containing all of the same code points, but also including
		// multi-code point characters (by using surrogate code points). We can
		// treat a UCS-2 encoded string as a UTF-16 encoded string, as long as
		// we reject out the UTF-16 specific code points. This matches the
		// BoringSSL behavior.

		if len(value)%2 != 0 {
			return "", errors.New("invalid BMPString")
		}

		// Strip terminator if present.
		if l := len(value); l >= 2 && value[l-1] == 0 && value[l-2] == 0 {
			value = value[:l-2]
		}

		s := make([]uint16, 0, len(value)/2)
		for len(value) > 0 {
			point := uint16(value[0])<<8 + uint16(value[1])
			// Reject UTF-16 code points that are permanently reserved
			// noncharacters (0xfffe, 0xffff, and 0xfdd0-0xfdef) and surrogates
			// (0xd800-0xdfff).
			if point == 0xfffe || point == 0xffff ||
				(point >= 0xfdd0 && point <= 0xfdef) ||
				(point >= 0xd800 && point <= 0xdfff) {
				return "", errors.New("invalid BMPString")
			}
			s = append(s, point)
			value = value[2:]
		}

		return string(utf16.Decode(s)), nil
	case pkix.IA5String:
		s := string(value)
		if isIA5String(s) != nil {
			return "", errors.New("invalid IA5String")
		}
		return asn1.IA5String(value), nil
	case pkix.Tag(asn1.TagNumericString):
		for _, b := range value {
			if !('0' <= b && b <= '9' || b == ' ') {
				return "", errors.New("invalid NumericString")
			}
		}
		return asn1.NUMERICString(value), nil
	}
	return "", fmt.Errorf("unsupported string type: %v", tag)
}

// parseName parses a DER encoded Name as defined in RFC 5280. We may
// want to export this function in the future for use in crypto/tls.
func parseName(raw pkix.String) (*pkix.RDNSequence, error) {
	if !raw.ReadASN1(&raw, pkix.SEQUENCE) {
		return nil, errors.New("x509: invalid RDNSequence")
	}

	var rdnSeq pkix.RDNSequence
	for !raw.Empty() {
		var rdnSet pkix.RelativeDistinguishedNameSET
		var set pkix.String
		if !raw.ReadASN1(&set, pkix.SET) {
			return nil, errors.New("x509: invalid RDNSequence")
		}
		for !set.Empty() {
			var atav pkix.String
			if !set.ReadASN1(&atav, pkix.SEQUENCE) {
				return nil, errors.New("x509: invalid RDNSequence: invalid attribute")
			}
			var attr pkix.AttributeTypeAndValue
			if !atav.ReadASN1ObjectIdentifier(&attr.Type) {
				return nil, errors.New("x509: invalid RDNSequence: invalid attribute type")
			}
			var rawValue pkix.String
			var valueTag pkix.Tag
			if !atav.ReadAnyASN1(&rawValue, &valueTag) {
				return nil, errors.New("x509: invalid RDNSequence: invalid attribute value")
			}
			var err error
			attr.Value, err = parseASN1String(valueTag, rawValue)
			if err != nil {
				return nil, fmt.Errorf("x509: invalid RDNSequence: invalid attribute value: %s", err)
			}
			rdnSet = append(rdnSet, attr)
		}

		rdnSeq = append(rdnSeq, rdnSet)
	}

	return &rdnSeq, nil
}

func parseAI(der pkix.String) (pkix.AlgorithmIdentifier, error) {
	ai := pkix.AlgorithmIdentifier{}
	if !der.ReadASN1ObjectIdentifier(&ai.Algorithm) {
		return ai, errors.New("x509: malformed OID")
	}
	if der.Empty() {
		return ai, nil
	}
	var params pkix.String
	var tag pkix.Tag
	if !der.ReadAnyASN1Element(&params, &tag) {
		return ai, errors.New("x509: malformed parameters")
	}
	ai.Parameters.Tag = int(tag)
	ai.Parameters.FullBytes = params
	return ai, nil
}

func parseTime(der *pkix.String) (time.Time, error) {
	var t time.Time
	switch {
	case der.PeekASN1Tag(pkix.UTCTime):
		if !der.ReadASN1UTCTime(&t) {
			return t, errors.New("x509: malformed UTCTime")
		}
	case der.PeekASN1Tag(pkix.GeneralizedTime):
		if !der.ReadASN1GeneralizedTime(&t) {
			return t, errors.New("x509: malformed GeneralizedTime")
		}
	default:
		return t, errors.New("x509: unsupported time format")
	}
	return t, nil
}

func parseValidity(der pkix.String) (time.Time, time.Time, error) {
	notBefore, err := parseTime(&der)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	notAfter, err := parseTime(&der)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}

	return notBefore, notAfter, nil
}

func parseExtension(der pkix.String) (pkix.Extension, error) {
	var ext pkix.Extension
	if !der.ReadASN1ObjectIdentifier(&ext.Id) {
		return ext, errors.New("x509: malformed extension OID field")
	}
	if der.PeekASN1Tag(pkix.BOOLEAN) {
		if !der.ReadASN1Boolean(&ext.Critical) {
			return ext, errors.New("x509: malformed extension critical field")
		}
	}
	var val pkix.String
	if !der.ReadASN1(&val, pkix.OCTET_STRING) {
		return ext, errors.New("x509: malformed extension value field")
	}
	ext.Value = val
	return ext, nil
}

func parsePublicKey(keyData *publicKeyInfo) (any, error) {
	oid := keyData.Algorithm.Algorithm
	params := keyData.Algorithm.Parameters
	data := keyData.PublicKey.RightAlign()
	switch {
	case oid.Equal(oidPublicKeyRSA):
		// RSA public keys must have a NULL in the parameters.
		// See RFC 3279, Section 2.3.1.
		if !bytes.Equal(params.FullBytes, asn1.NullBytes) {
			return nil, errors.New("x509: RSA key missing NULL parameters")
		}

		der := pkix.String(data)
		p := &pkcs1PublicKey{N: new(big.Int)}
		if !der.ReadASN1(&der, pkix.SEQUENCE) {
			return nil, errors.New("x509: invalid RSA public key")
		}
		if !der.ReadASN1Integer(p.N) {
			return nil, errors.New("x509: invalid RSA modulus")
		}
		if !der.ReadASN1Integer(&p.E) {
			return nil, errors.New("x509: invalid RSA public exponent")
		}

		if p.N.Sign() <= 0 {
			return nil, errors.New("x509: RSA modulus is not a positive number")
		}
		if p.E <= 0 {
			return nil, errors.New("x509: RSA public exponent is not a positive number")
		}

		pub := &rsa.PublicKey{
			E: p.E,
			N: p.N,
		}
		return pub, nil
	case oid.Equal(oidPublicKeyECDSA):
		paramsDer := pkix.String(params.FullBytes)
		namedCurveOID := new(asn1.ObjectIdentifier)
		if !paramsDer.ReadASN1ObjectIdentifier(namedCurveOID) {
			return nil, errors.New("x509: invalid ECDSA parameters")
		}
		namedCurve := namedCurveFromOID(*namedCurveOID)
		if namedCurve == nil {
			return nil, errors.New("x509: unsupported elliptic curve")
		}
		return ecdsa.ParseUncompressedPublicKey(namedCurve, data)
	case oid.Equal(oidPublicKeyEd25519):
		// RFC 8410, Section 3
		// > For all of the OIDs, the parameters MUST be absent.
		if len(params.FullBytes) != 0 {
			return nil, errors.New("x509: Ed25519 key encoded with illegal parameters")
		}
		if len(data) != ed25519.PublicKeySize {
			return nil, errors.New("x509: wrong Ed25519 public key size")
		}
		return ed25519.PublicKey(data), nil
	case oid.Equal(oidPublicKeyX25519):
		// RFC 8410, Section 3
		// > For all of the OIDs, the parameters MUST be absent.
		if len(params.FullBytes) != 0 {
			return nil, errors.New("x509: X25519 key encoded with illegal parameters")
		}
		return ecdh.X25519().NewPublicKey(data)
	case oid.Equal(oidPublicKeyDSA):
		der := pkix.String(data)
		y := new(big.Int)
		if !der.ReadASN1Integer(y) {
			return nil, errors.New("x509: invalid DSA public key")
		}
		pub := &dsa.PublicKey{
			Y: y,
			Parameters: dsa.Parameters{
				P: new(big.Int),
				Q: new(big.Int),
				G: new(big.Int),
			},
		}
		paramsDer := pkix.String(params.FullBytes)
		if !paramsDer.ReadASN1(&paramsDer, pkix.SEQUENCE) ||
			!paramsDer.ReadASN1Integer(pub.Parameters.P) ||
			!paramsDer.ReadASN1Integer(pub.Parameters.Q) ||
			!paramsDer.ReadASN1Integer(pub.Parameters.G) {
			return nil, errors.New("x509: invalid DSA parameters")
		}
		if pub.Y.Sign() <= 0 || pub.Parameters.P.Sign() <= 0 ||
			pub.Parameters.Q.Sign() <= 0 || pub.Parameters.G.Sign() <= 0 {
			return nil, errors.New("x509: zero or negative DSA parameter")
		}
		return pub, nil
	default:
		return nil, errors.New("x509: unknown public key algorithm")
	}
}

func parseKeyUsageExtension(der pkix.String) (KeyUsage, error) {
	var usageBits asn1.BitString
	if !der.ReadASN1BitString(&usageBits) {
		return 0, errors.New("x509: invalid key usage")
	}

	var usage int
	for i := 0; i < 9; i++ {
		if usageBits.At(i) != 0 {
			usage |= 1 << uint(i)
		}
	}
	return KeyUsage(usage), nil
}

func parseBasicConstraintsExtension(der pkix.String) (bool, int, error) {
	var isCA bool
	if !der.ReadASN1(&der, pkix.SEQUENCE) {
		return false, 0, errors.New("x509: invalid basic constraints")
	}
	if der.PeekASN1Tag(pkix.BOOLEAN) {
		if !der.ReadASN1Boolean(&isCA) {
			return false, 0, errors.New("x509: invalid basic constraints")
		}
	}

	maxPathLen := -1
	if der.PeekASN1Tag(pkix.INTEGER) {
		var mpl uint
		if !der.ReadASN1Integer(&mpl) || mpl > math.MaxInt {
			return false, 0, errors.New("x509: invalid basic constraints")
		}
		maxPathLen = int(mpl)
	}

	return isCA, maxPathLen, nil
}

func forEachSAN(der pkix.String, callback func(tag int, data []byte) error) error {
	if !der.ReadASN1(&der, pkix.SEQUENCE) {
		return errors.New("x509: invalid subject alternative names")
	}
	for !der.Empty() {
		var san pkix.String
		var tag pkix.Tag
		if !der.ReadAnyASN1(&san, &tag) {
			return errors.New("x509: invalid subject alternative name")
		}
		if err := callback(int(tag&0x1F), san); err != nil {
			return err
		}
	}

	return nil
}

func parseSANExtension(der pkix.String) (dnsNames, emailAddresses []string, ipAddresses []net.IP, uris []*url.URL,
	otherNames []pkix.OtherName, registredID []pkix.RegisterID, directoryName []pkix.Name, err error) {
	err = forEachSAN(der, func(tag int, data []byte) error {
		switch tag {
		case nameTypeOther:
			var otherName pkix.OtherName
			var rest []byte
			rest, err = asn1.Unmarshal(data, &otherName.Type)
			if err != nil && len(rest) == 0 {
				return errors.New("x509: SAN otherName is malformed")
			}
			rest, err = asn1.Unmarshal(rest, &otherName.Value)
			if err != nil && len(rest) > 0 {
				return errors.New("x509: SAN otherName is malformed")
			}
			otherNames = append(otherNames, otherName)
		case nameTypeEmail:
			email := string(data)
			if err := isIA5String(email); err != nil {
				return errors.New("x509: SAN rfc822Name is malformed")
			}
			emailAddresses = append(emailAddresses, email)
		case nameTypeDNS:
			name := string(data)
			if err := isIA5String(name); err != nil {
				return errors.New("x509: SAN dNSName is malformed")
			}
			dnsNames = append(dnsNames, string(name))
		case nameTypeDirectory:
			var rawName *pkix.RDNSequence
			var name pkix.Name
			rawName, err = parseName(pkix.String(data))
			if err != nil {
				return errors.New("x509: SAN directoryName is malformed")
			}
			name.FillFromRDNSequence(rawName)
			directoryName = append(directoryName, name)
		case nameTypeURI:
			uriStr := string(data)
			if err := isIA5String(uriStr); err != nil {
				return errors.New("x509: SAN uniformResourceIdentifier is malformed")
			}
			uri, err := url.Parse(uriStr)
			if err != nil {
				return fmt.Errorf("x509: cannot parse URI %q: %s", uriStr, err)
			}
			if len(uri.Host) > 0 && !domainNameValid(uri.Host, false) {
				return fmt.Errorf("x509: cannot parse URI %q: invalid domain", uriStr)
			}
			uris = append(uris, uri)
		case nameTypeIP:
			switch len(data) {
			case net.IPv4len, net.IPv6len:
				ipAddresses = append(ipAddresses, data)
			default:
				return errors.New("x509: cannot parse IP address of length " + strconv.Itoa(len(data)))
			}
		case nameTypeRegisterID:
			var oid pkix.RegisterID
			if !oid.ReadASN1(pkix.String(data)) {
				return errors.New("x509: SAN registerID is malformed")
			}
			registredID = append(registredID, oid)
		}

		return nil
	})

	return
}

func parseAuthorityKeyIdentifier(e pkix.Extension) ([]byte, error) {
	// RFC 5280, Section 4.2.1.1
	if e.Critical {
		// Conforming CAs MUST mark this extension as non-critical
		return nil, errors.New("x509: authority key identifier incorrectly marked critical")
	}
	val := pkix.String(e.Value)
	var akid pkix.String
	if !val.ReadASN1(&akid, pkix.SEQUENCE) {
		return nil, errors.New("x509: invalid authority key identifier")
	}
	if akid.PeekASN1Tag(pkix.Tag(0).ContextSpecific()) {
		if !akid.ReadASN1(&akid, pkix.Tag(0).ContextSpecific()) {
			return nil, errors.New("x509: invalid authority key identifier")
		}
		return akid, nil
	}
	return nil, nil
}

func parseExtKeyUsageExtension(der pkix.String) ([]ExtKeyUsage, []asn1.ObjectIdentifier, error) {
	var extKeyUsages []ExtKeyUsage
	var unknownUsages []asn1.ObjectIdentifier
	if !der.ReadASN1(&der, pkix.SEQUENCE) {
		return nil, nil, errors.New("x509: invalid extended key usages")
	}
	for !der.Empty() {
		var eku asn1.ObjectIdentifier
		if !der.ReadASN1ObjectIdentifier(&eku) {
			return nil, nil, errors.New("x509: invalid extended key usages")
		}
		if extKeyUsage, ok := extKeyUsageFromOID(eku); ok {
			extKeyUsages = append(extKeyUsages, extKeyUsage)
		} else {
			unknownUsages = append(unknownUsages, eku)
		}
	}
	return extKeyUsages, unknownUsages, nil
}

func parseCertificatePoliciesExtension(der pkix.String) ([]OID, error) {
	var oids []OID
	seenOIDs := map[string]bool{}
	if !der.ReadASN1(&der, pkix.SEQUENCE) {
		return nil, errors.New("x509: invalid certificate policies")
	}
	for !der.Empty() {
		var cp pkix.String
		var OIDBytes pkix.String
		if !der.ReadASN1(&cp, pkix.SEQUENCE) || !cp.ReadASN1(&OIDBytes, pkix.OBJECT_IDENTIFIER) {
			return nil, errors.New("x509: invalid certificate policies")
		}
		if seenOIDs[string(OIDBytes)] {
			return nil, errors.New("x509: invalid certificate policies")
		}
		seenOIDs[string(OIDBytes)] = true
		oid, ok := newOIDFromDER(OIDBytes)
		if !ok {
			return nil, errors.New("x509: invalid certificate policies")
		}
		oids = append(oids, oid)
	}
	return oids, nil
}

// isValidIPMask reports whether mask consists of zero or more 1 bits, followed by zero bits.
func isValidIPMask(mask []byte) bool {
	seenZero := false

	for _, b := range mask {
		if seenZero {
			if b != 0 {
				return false
			}

			continue
		}

		switch b {
		case 0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe:
			seenZero = true
		case 0xff:
		default:
			return false
		}
	}

	return true
}

func parseNameConstraintsExtension(out *Certificate, e pkix.Extension) (unhandled bool, err error) {
	// RFC 5280, 4.2.1.10

	// NameConstraints ::= SEQUENCE {
	//      permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
	//      excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
	//
	// GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
	//
	// GeneralSubtree ::= SEQUENCE {
	//      base                    GeneralName,
	//      minimum         [0]     BaseDistance DEFAULT 0,
	//      maximum         [1]     BaseDistance OPTIONAL }
	//
	// BaseDistance ::= INTEGER (0..MAX)

	outer := pkix.String(e.Value)
	var toplevel, permitted, excluded pkix.String
	var havePermitted, haveExcluded bool
	if !outer.ReadASN1(&toplevel, pkix.SEQUENCE) ||
		!outer.Empty() ||
		!toplevel.ReadOptionalASN1(&permitted, &havePermitted, pkix.Tag(0).ContextSpecific().Constructed()) ||
		!toplevel.ReadOptionalASN1(&excluded, &haveExcluded, pkix.Tag(1).ContextSpecific().Constructed()) ||
		!toplevel.Empty() {
		return false, errors.New("x509: invalid NameConstraints extension")
	}

	if !havePermitted && !haveExcluded || len(permitted) == 0 && len(excluded) == 0 {
		// From RFC 5280, Section 4.2.1.10:
		//   “either the permittedSubtrees field
		//   or the excludedSubtrees MUST be
		//   present”
		return false, errors.New("x509: empty name constraints extension")
	}

	getValues := func(subtrees pkix.String) (dnsNames []string, ips []*net.IPNet, emails, uriDomains []string, err error) {
		for !subtrees.Empty() {
			var seq, value pkix.String
			var tag pkix.Tag
			if !subtrees.ReadASN1(&seq, pkix.SEQUENCE) ||
				!seq.ReadAnyASN1(&value, &tag) {
				return nil, nil, nil, nil, fmt.Errorf("x509: invalid NameConstraints extension")
			}

			var (
				dnsTag   = pkix.Tag(2).ContextSpecific()
				emailTag = pkix.Tag(1).ContextSpecific()
				ipTag    = pkix.Tag(7).ContextSpecific()
				uriTag   = pkix.Tag(6).ContextSpecific()
			)

			switch tag {
			case dnsTag:
				domain := string(value)
				if err := isIA5String(domain); err != nil {
					return nil, nil, nil, nil, errors.New("x509: invalid constraint value: " + err.Error())
				}

				if !domainNameValid(domain, true) {
					return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse dnsName constraint %q", domain)
				}
				dnsNames = append(dnsNames, domain)

			case ipTag:
				l := len(value)
				var ip, mask []byte

				switch l {
				case 8:
					ip = value[:4]
					mask = value[4:]

				case 32:
					ip = value[:16]
					mask = value[16:]

				default:
					return nil, nil, nil, nil, fmt.Errorf("x509: IP constraint contained value of length %d", l)
				}

				if !isValidIPMask(mask) {
					return nil, nil, nil, nil, fmt.Errorf("x509: IP constraint contained invalid mask %x", mask)
				}

				ips = append(ips, &net.IPNet{IP: net.IP(ip), Mask: net.IPMask(mask)})

			case emailTag:
				constraint := string(value)
				if err := isIA5String(constraint); err != nil {
					return nil, nil, nil, nil, errors.New("x509: invalid constraint value: " + err.Error())
				}

				// If the constraint contains an @ then
				// it specifies an exact mailbox name.
				if strings.Contains(constraint, "@") {
					if _, ok := parseRFC2821Mailbox(constraint); !ok {
						return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse rfc822Name constraint %q", constraint)
					}
				} else {
					if !domainNameValid(constraint, true) {
						return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse rfc822Name constraint %q", constraint)
					}
				}
				emails = append(emails, constraint)

			case uriTag:
				domain := string(value)
				if err := isIA5String(domain); err != nil {
					return nil, nil, nil, nil, errors.New("x509: invalid constraint value: " + err.Error())
				}

				if net.ParseIP(domain) != nil {
					return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse URI constraint %q: cannot be IP address", domain)
				}

				if !domainNameValid(domain, true) {
					return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse URI constraint %q", domain)
				}
				uriDomains = append(uriDomains, domain)

			default:
				unhandled = true
			}
		}

		return dnsNames, ips, emails, uriDomains, nil
	}

	if out.PermittedDNSDomains, out.PermittedIPRanges, out.PermittedEmailAddresses, out.PermittedURIDomains, err = getValues(permitted); err != nil {
		return false, err
	}
	if out.ExcludedDNSDomains, out.ExcludedIPRanges, out.ExcludedEmailAddresses, out.ExcludedURIDomains, err = getValues(excluded); err != nil {
		return false, err
	}
	out.PermittedDNSDomainsCritical = e.Critical

	return unhandled, nil
}

func processExtensions(out *Certificate) error {
	var err error
	for _, e := range out.Extensions {
		unhandled := false

		if len(e.Id) == 4 && e.Id[0] == 2 && e.Id[1] == 5 && e.Id[2] == 29 {
			switch e.Id[3] {
			case 15:
				out.KeyUsage, err = parseKeyUsageExtension(e.Value)
				if err != nil {
					return err
				}
			case 19:
				out.IsCA, out.MaxPathLen, err = parseBasicConstraintsExtension(e.Value)
				if err != nil {
					return err
				}
				out.BasicConstraintsValid = true
				out.MaxPathLenZero = out.MaxPathLen == 0
			case 17:
				out.DNSNames, out.EmailAddresses, out.IPAddresses, out.URIs, out.OtherNames, out.RegisterIDs, out.DirectoryNames, err = parseSANExtension(e.Value)
				if err != nil {
					return err
				}

				if len(out.DNSNames) == 0 && len(out.EmailAddresses) == 0 && len(out.IPAddresses) == 0 && len(out.URIs) == 0 {
					// If we didn't parse anything then we do the critical check, below.
					unhandled = true
				}

			case 30:
				unhandled, err = parseNameConstraintsExtension(out, e)
				if err != nil {
					return err
				}

			case 31:
				// RFC 5280, 4.2.1.13

				// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
				//
				// DistributionPoint ::= SEQUENCE {
				//     distributionPoint       [0]     DistributionPointName OPTIONAL,
				//     reasons                 [1]     ReasonFlags OPTIONAL,
				//     cRLIssuer               [2]     GeneralNames OPTIONAL }
				//
				// DistributionPointName ::= CHOICE {
				//     fullName                [0]     GeneralNames,
				//     nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
				val := pkix.String(e.Value)
				if !val.ReadASN1(&val, pkix.SEQUENCE) {
					return errors.New("x509: invalid CRL distribution points")
				}
				for !val.Empty() {
					var dpDER pkix.String
					if !val.ReadASN1(&dpDER, pkix.SEQUENCE) {
						return errors.New("x509: invalid CRL distribution point")
					}
					var dpNameDER pkix.String
					var dpNamePresent bool
					if !dpDER.ReadOptionalASN1(&dpNameDER, &dpNamePresent, pkix.Tag(0).Constructed().ContextSpecific()) {
						return errors.New("x509: invalid CRL distribution point")
					}
					if !dpNamePresent {
						continue
					}
					if !dpNameDER.ReadASN1(&dpNameDER, pkix.Tag(0).Constructed().ContextSpecific()) {
						return errors.New("x509: invalid CRL distribution point")
					}
					for !dpNameDER.Empty() {
						if !dpNameDER.PeekASN1Tag(pkix.Tag(6).ContextSpecific()) {
							break
						}
						var uri pkix.String
						if !dpNameDER.ReadASN1(&uri, pkix.Tag(6).ContextSpecific()) {
							return errors.New("x509: invalid CRL distribution point")
						}
						out.CRLDistributionPoints = append(out.CRLDistributionPoints, string(uri))
					}
				}

			case 35:
				out.AuthorityKeyId, err = parseAuthorityKeyIdentifier(e)
				if err != nil {
					return err
				}
			case 36:
				val := pkix.String(e.Value)
				if !val.ReadASN1(&val, pkix.SEQUENCE) {
					return errors.New("x509: invalid policy constraints extension")
				}
				if val.PeekASN1Tag(pkix.Tag(0).ContextSpecific()) {
					var v int64
					if !val.ReadASN1Int64WithTag(&v, pkix.Tag(0).ContextSpecific()) {
						return errors.New("x509: invalid policy constraints extension")
					}
					out.RequireExplicitPolicy = int(v)
					// Check for overflow.
					if int64(out.RequireExplicitPolicy) != v {
						return errors.New("x509: policy constraints requireExplicitPolicy field overflows int")
					}
					out.RequireExplicitPolicyZero = out.RequireExplicitPolicy == 0
				}
				if val.PeekASN1Tag(pkix.Tag(1).ContextSpecific()) {
					var v int64
					if !val.ReadASN1Int64WithTag(&v, pkix.Tag(1).ContextSpecific()) {
						return errors.New("x509: invalid policy constraints extension")
					}
					out.InhibitPolicyMapping = int(v)
					// Check for overflow.
					if int64(out.InhibitPolicyMapping) != v {
						return errors.New("x509: policy constraints inhibitPolicyMapping field overflows int")
					}
					out.InhibitPolicyMappingZero = out.InhibitPolicyMapping == 0
				}
			case 37:
				out.ExtKeyUsage, out.UnknownExtKeyUsage, err = parseExtKeyUsageExtension(e.Value)
				if err != nil {
					return err
				}
			case 14: // RFC 5280, 4.2.1.2
				if e.Critical {
					// Conforming CAs MUST mark this extension as non-critical
					return errors.New("x509: subject key identifier incorrectly marked critical")
				}
				val := pkix.String(e.Value)
				var skid pkix.String
				if !val.ReadASN1(&skid, pkix.OCTET_STRING) {
					return errors.New("x509: invalid subject key identifier")
				}
				out.SubjectKeyId = skid
			case 32:
				out.Policies, err = parseCertificatePoliciesExtension(e.Value)
				if err != nil {
					return err
				}
				out.PolicyIdentifiers = make([]asn1.ObjectIdentifier, 0, len(out.Policies))
				for _, oid := range out.Policies {
					if oid, ok := oid.toASN1OID(); ok {
						out.PolicyIdentifiers = append(out.PolicyIdentifiers, oid)
					}
				}
			case 33:
				val := pkix.String(e.Value)
				if !val.ReadASN1(&val, pkix.SEQUENCE) {
					return errors.New("x509: invalid policy mappings extension")
				}
				for !val.Empty() {
					var s pkix.String
					var issuer, subject pkix.String
					if !val.ReadASN1(&s, pkix.SEQUENCE) ||
						!s.ReadASN1(&issuer, pkix.OBJECT_IDENTIFIER) ||
						!s.ReadASN1(&subject, pkix.OBJECT_IDENTIFIER) {
						return errors.New("x509: invalid policy mappings extension")
					}
					out.PolicyMappings = append(out.PolicyMappings, PolicyMapping{OID{issuer}, OID{subject}})
				}
			case 54:
				val := pkix.String(e.Value)
				if !val.ReadASN1Integer(&out.InhibitAnyPolicy) {
					return errors.New("x509: invalid inhibit any policy extension")
				}
				out.InhibitAnyPolicyZero = out.InhibitAnyPolicy == 0
			default:
				// Unknown extensions are recorded if critical.
				unhandled = true
			}
		} else if e.Id.Equal(oidExtensionAuthorityInfoAccess) {
			// RFC 5280 4.2.2.1: Authority Information Access
			if e.Critical {
				// Conforming CAs MUST mark this extension as non-critical
				return errors.New("x509: authority info access incorrectly marked critical")
			}
			val := pkix.String(e.Value)
			if !val.ReadASN1(&val, pkix.SEQUENCE) {
				return errors.New("x509: invalid authority info access")
			}
			for !val.Empty() {
				var aiaDER pkix.String
				if !val.ReadASN1(&aiaDER, pkix.SEQUENCE) {
					return errors.New("x509: invalid authority info access")
				}
				var method asn1.ObjectIdentifier
				if !aiaDER.ReadASN1ObjectIdentifier(&method) {
					return errors.New("x509: invalid authority info access")
				}
				if !aiaDER.PeekASN1Tag(pkix.Tag(6).ContextSpecific()) {
					continue
				}
				if !aiaDER.ReadASN1(&aiaDER, pkix.Tag(6).ContextSpecific()) {
					return errors.New("x509: invalid authority info access")
				}
				switch {
				case method.Equal(oidAuthorityInfoAccessOcsp):
					out.OCSPServer = append(out.OCSPServer, string(aiaDER))
				case method.Equal(oidAuthorityInfoAccessIssuers):
					out.IssuingCertificateURL = append(out.IssuingCertificateURL, string(aiaDER))
				}
			}
		} else {
			// Unknown extensions are recorded if critical.
			unhandled = true
		}

		if e.Critical && unhandled {
			out.UnhandledCriticalExtensions = append(out.UnhandledCriticalExtensions, e.Id)
		}
	}

	return nil
}

func parseCertificate(der []byte) (*Certificate, error) {
	cert := &Certificate{}

	input := pkix.String(der)
	// we read the SEQUENCE including length and tag bytes so that
	// we can populate Certificate.Raw, before unwrapping the
	// SEQUENCE so it can be operated on
	if !input.ReadASN1Element(&input, pkix.SEQUENCE) {
		return nil, errors.New("x509: malformed certificate")
	}
	cert.Raw = input
	if !input.ReadASN1(&input, pkix.SEQUENCE) {
		return nil, errors.New("x509: malformed certificate")
	}

	var tbs pkix.String
	// do the same trick again as above to extract the raw
	// bytes for Certificate.RawTBSCertificate
	if !input.ReadASN1Element(&tbs, pkix.SEQUENCE) {
		return nil, errors.New("x509: malformed tbs certificate")
	}
	cert.RawTBSCertificate = tbs
	if !tbs.ReadASN1(&tbs, pkix.SEQUENCE) {
		return nil, errors.New("x509: malformed tbs certificate")
	}

	if !tbs.ReadOptionalASN1Integer(&cert.Version, pkix.Tag(0).Constructed().ContextSpecific(), 0) {
		return nil, errors.New("x509: malformed version")
	}
	if cert.Version < 0 {
		return nil, errors.New("x509: malformed version")
	}
	// for backwards compat reasons Version is one-indexed,
	// rather than zero-indexed as defined in 5280
	cert.Version++
	if cert.Version > 3 {
		return nil, errors.New("x509: invalid version")
	}

	serial := new(big.Int)
	if !tbs.ReadASN1Integer(serial) {
		return nil, errors.New("x509: malformed serial number")
	}
	if serial.Sign() == -1 {
		return nil, errors.New("x509: negative serial number")
	}
	cert.SerialNumber = serial

	var sigAISeq pkix.String
	if !tbs.ReadASN1(&sigAISeq, pkix.SEQUENCE) {
		return nil, errors.New("x509: malformed signature algorithm identifier")
	}
	// Before parsing the inner algorithm identifier, extract
	// the outer algorithm identifier and make sure that they
	// match.
	var outerSigAISeq pkix.String
	if !input.ReadASN1(&outerSigAISeq, pkix.SEQUENCE) {
		return nil, errors.New("x509: malformed algorithm identifier")
	}
	if !bytes.Equal(outerSigAISeq, sigAISeq) {
		return nil, errors.New("x509: inner and outer signature algorithm identifiers don't match")
	}
	sigAI, err := parseAI(sigAISeq)
	if err != nil {
		return nil, err
	}
	cert.SignatureAlgorithm = getSignatureAlgorithmFromAI(sigAI)

	var issuerSeq pkix.String
	if !tbs.ReadASN1Element(&issuerSeq, pkix.SEQUENCE) {
		return nil, errors.New("x509: malformed issuer")
	}
	cert.RawIssuer = issuerSeq
	issuerRDNs, err := parseName(issuerSeq)
	if err != nil {
		return nil, err
	}
	cert.Issuer.FillFromRDNSequence(issuerRDNs)

	var validity pkix.String
	if !tbs.ReadASN1(&validity, pkix.SEQUENCE) {
		return nil, errors.New("x509: malformed validity")
	}
	cert.NotBefore, cert.NotAfter, err = parseValidity(validity)
	if err != nil {
		return nil, err
	}

	var subjectSeq pkix.String
	if !tbs.ReadASN1Element(&subjectSeq, pkix.SEQUENCE) {
		return nil, errors.New("x509: malformed issuer")
	}
	cert.RawSubject = subjectSeq
	subjectRDNs, err := parseName(subjectSeq)
	if err != nil {
		return nil, err
	}
	cert.Subject.FillFromRDNSequence(subjectRDNs)

	var spki pkix.String
	if !tbs.ReadASN1Element(&spki, pkix.SEQUENCE) {
		return nil, errors.New("x509: malformed spki")
	}
	cert.RawSubjectPublicKeyInfo = spki
	if !spki.ReadASN1(&spki, pkix.SEQUENCE) {
		return nil, errors.New("x509: malformed spki")
	}
	var pkAISeq pkix.String
	if !spki.ReadASN1(&pkAISeq, pkix.SEQUENCE) {
		return nil, errors.New("x509: malformed public key algorithm identifier")
	}
	pkAI, err := parseAI(pkAISeq)
	if err != nil {
		return nil, err
	}
	cert.PublicKeyAlgorithm = getPublicKeyAlgorithmFromOID(pkAI.Algorithm)
	var spk asn1.BitString
	if !spki.ReadASN1BitString(&spk) {
		return nil, errors.New("x509: malformed subjectPublicKey")
	}
	if cert.PublicKeyAlgorithm != UnknownPublicKeyAlgorithm {
		cert.PublicKey, err = parsePublicKey(&publicKeyInfo{
			Algorithm: pkAI,
			PublicKey: spk,
		})
		if err != nil {
			return nil, err
		}
	}

	if cert.Version > 1 {
		if !tbs.SkipOptionalASN1(pkix.Tag(1).ContextSpecific()) {
			return nil, errors.New("x509: malformed issuerUniqueID")
		}
		if !tbs.SkipOptionalASN1(pkix.Tag(2).ContextSpecific()) {
			return nil, errors.New("x509: malformed subjectUniqueID")
		}
		if cert.Version == 3 {
			var extensions pkix.String
			var present bool
			if !tbs.ReadOptionalASN1(&extensions, &present, pkix.Tag(3).Constructed().ContextSpecific()) {
				return nil, errors.New("x509: malformed extensions")
			}
			if present {
				seenExts := make(map[string]bool)
				if !extensions.ReadASN1(&extensions, pkix.SEQUENCE) {
					return nil, errors.New("x509: malformed extensions")
				}
				for !extensions.Empty() {
					var extension pkix.String
					if !extensions.ReadASN1(&extension, pkix.SEQUENCE) {
						return nil, errors.New("x509: malformed extension")
					}
					ext, err := parseExtension(extension)
					if err != nil {
						return nil, err
					}
					oidStr := ext.Id.String()
					if seenExts[oidStr] {
						return nil, fmt.Errorf("x509: certificate contains duplicate extension with OID %q", oidStr)
					}
					seenExts[oidStr] = true
					cert.Extensions = append(cert.Extensions, ext)
				}
				err = processExtensions(cert)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	var signature asn1.BitString
	if !input.ReadASN1BitString(&signature) {
		return nil, errors.New("x509: malformed signature")
	}
	cert.Signature = signature.RightAlign()

	return cert, nil
}

// ParseCertificate parses a single certificate from the given ASN.1 DER data.
func ParseCertificate(der []byte) (*Certificate, error) {
	cert, err := parseCertificate(der)
	if err != nil {
		return nil, err
	}
	if len(der) != len(cert.Raw) {
		return nil, errors.New("x509: trailing data")
	}
	return cert, nil
}

// ParseCertificates parses one or more certificates from the given ASN.1 DER
// data. The certificates must be concatenated with no intermediate padding.
func ParseCertificates(der []byte) ([]*Certificate, error) {
	var certs []*Certificate
	for len(der) > 0 {
		cert, err := parseCertificate(der)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		der = der[len(cert.Raw):]
	}
	return certs, nil
}

// The X.509 standards confusingly 1-indexed the version names, but 0-indexed
// the actual encoded version, so the version for X.509v2 is 1.
const x509v2Version = 1

// ParseRevocationList parses a X509 v2 [Certificate] Revocation List from the given
// ASN.1 DER data.
func ParseRevocationList(der []byte) (*RevocationList, error) {
	rl := &RevocationList{}

	input := pkix.String(der)
	// we read the SEQUENCE including length and tag bytes so that
	// we can populate RevocationList.Raw, before unwrapping the
	// SEQUENCE so it can be operated on
	if !input.ReadASN1Element(&input, pkix.SEQUENCE) {
		return nil, errors.New("x509: malformed crl")
	}
	rl.Raw = input
	if !input.ReadASN1(&input, pkix.SEQUENCE) {
		return nil, errors.New("x509: malformed crl")
	}

	var tbs pkix.String
	// do the same trick again as above to extract the raw
	// bytes for Certificate.RawTBSCertificate
	if !input.ReadASN1Element(&tbs, pkix.SEQUENCE) {
		return nil, errors.New("x509: malformed tbs crl")
	}
	rl.RawTBSRevocationList = tbs
	if !tbs.ReadASN1(&tbs, pkix.SEQUENCE) {
		return nil, errors.New("x509: malformed tbs crl")
	}

	var version int
	if !tbs.PeekASN1Tag(pkix.INTEGER) {
		return nil, errors.New("x509: unsupported crl version")
	}
	if !tbs.ReadASN1Integer(&version) {
		return nil, errors.New("x509: malformed crl")
	}
	if version != x509v2Version {
		return nil, fmt.Errorf("x509: unsupported crl version: %d", version)
	}

	var sigAISeq pkix.String
	if !tbs.ReadASN1(&sigAISeq, pkix.SEQUENCE) {
		return nil, errors.New("x509: malformed signature algorithm identifier")
	}
	// Before parsing the inner algorithm identifier, extract
	// the outer algorithm identifier and make sure that they
	// match.
	var outerSigAISeq pkix.String
	if !input.ReadASN1(&outerSigAISeq, pkix.SEQUENCE) {
		return nil, errors.New("x509: malformed algorithm identifier")
	}
	if !bytes.Equal(outerSigAISeq, sigAISeq) {
		return nil, errors.New("x509: inner and outer signature algorithm identifiers don't match")
	}
	sigAI, err := parseAI(sigAISeq)
	if err != nil {
		return nil, err
	}
	rl.SignatureAlgorithm = getSignatureAlgorithmFromAI(sigAI)

	var signature asn1.BitString
	if !input.ReadASN1BitString(&signature) {
		return nil, errors.New("x509: malformed signature")
	}
	rl.Signature = signature.RightAlign()

	var issuerSeq pkix.String
	if !tbs.ReadASN1Element(&issuerSeq, pkix.SEQUENCE) {
		return nil, errors.New("x509: malformed issuer")
	}
	rl.RawIssuer = issuerSeq
	issuerRDNs, err := parseName(issuerSeq)
	if err != nil {
		return nil, err
	}
	rl.Issuer.FillFromRDNSequence(issuerRDNs)

	rl.ThisUpdate, err = parseTime(&tbs)
	if err != nil {
		return nil, err
	}
	if tbs.PeekASN1Tag(pkix.GeneralizedTime) || tbs.PeekASN1Tag(pkix.UTCTime) {
		rl.NextUpdate, err = parseTime(&tbs)
		if err != nil {
			return nil, err
		}
	}

	if tbs.PeekASN1Tag(pkix.SEQUENCE) {
		var revokedSeq pkix.String
		if !tbs.ReadASN1(&revokedSeq, pkix.SEQUENCE) {
			return nil, errors.New("x509: malformed crl")
		}
		for !revokedSeq.Empty() {
			rce := RevocationListEntry{}

			var certSeq pkix.String
			if !revokedSeq.ReadASN1Element(&certSeq, pkix.SEQUENCE) {
				return nil, errors.New("x509: malformed crl")
			}
			rce.Raw = certSeq
			if !certSeq.ReadASN1(&certSeq, pkix.SEQUENCE) {
				return nil, errors.New("x509: malformed crl")
			}

			rce.SerialNumber = new(big.Int)
			if !certSeq.ReadASN1Integer(rce.SerialNumber) {
				return nil, errors.New("x509: malformed serial number")
			}
			rce.RevocationTime, err = parseTime(&certSeq)
			if err != nil {
				return nil, err
			}
			var extensions pkix.String
			var present bool
			if !certSeq.ReadOptionalASN1(&extensions, &present, pkix.SEQUENCE) {
				return nil, errors.New("x509: malformed extensions")
			}
			if present {
				for !extensions.Empty() {
					var extension pkix.String
					if !extensions.ReadASN1(&extension, pkix.SEQUENCE) {
						return nil, errors.New("x509: malformed extension")
					}
					ext, err := parseExtension(extension)
					if err != nil {
						return nil, err
					}
					if ext.Id.Equal(oidExtensionReasonCode) {
						val := pkix.String(ext.Value)
						if !val.ReadASN1Enum(&rce.ReasonCode) {
							return nil, fmt.Errorf("x509: malformed reasonCode extension")
						}
					}
					rce.Extensions = append(rce.Extensions, ext)
				}
			}

			rl.RevokedCertificateEntries = append(rl.RevokedCertificateEntries, rce)
			rcDeprecated := pkix.RevokedCertificate{
				SerialNumber:   rce.SerialNumber,
				RevocationTime: rce.RevocationTime,
				Extensions:     rce.Extensions,
			}
			rl.RevokedCertificates = append(rl.RevokedCertificates, rcDeprecated)
		}
	}

	var extensions pkix.String
	var present bool
	if !tbs.ReadOptionalASN1(&extensions, &present, pkix.Tag(0).Constructed().ContextSpecific()) {
		return nil, errors.New("x509: malformed extensions")
	}
	if present {
		if !extensions.ReadASN1(&extensions, pkix.SEQUENCE) {
			return nil, errors.New("x509: malformed extensions")
		}
		for !extensions.Empty() {
			var extension pkix.String
			if !extensions.ReadASN1(&extension, pkix.SEQUENCE) {
				return nil, errors.New("x509: malformed extension")
			}
			ext, err := parseExtension(extension)
			if err != nil {
				return nil, err
			}
			if ext.Id.Equal(oidExtensionAuthorityKeyId) {
				rl.AuthorityKeyId, err = parseAuthorityKeyIdentifier(ext)
				if err != nil {
					return nil, err
				}
			} else if ext.Id.Equal(oidExtensionCRLNumber) {
				value := pkix.String(ext.Value)
				rl.Number = new(big.Int)
				if !value.ReadASN1Integer(rl.Number) {
					return nil, errors.New("x509: malformed crl number")
				}
			}
			rl.Extensions = append(rl.Extensions, ext)
		}
	}

	return rl, nil
}

// domainNameValid is an alloc-less version of the checks that
// domainToReverseLabels does.
func domainNameValid(s string, constraint bool) bool {
	// TODO(#75835): This function omits a number of checks which we
	// really should be doing to enforce that domain names are valid names per
	// RFC 1034. We previously enabled these checks, but this broke a
	// significant number of certificates we previously considered valid, and we
	// happily create via CreateCertificate (et al). We should enable these
	// checks, but will need to gate them behind a GODEBUG.
	//
	// I have left the checks we previously enabled, noted with "TODO(#75835)" so
	// that we can easily re-enable them once we unbreak everyone.

	// TODO(#75835): this should only be true for constraints.
	if len(s) == 0 {
		return true
	}

	// Do not allow trailing period (FQDN format is not allowed in SANs or
	// constraints).
	if s[len(s)-1] == '.' {
		return false
	}

	// TODO(#75835): domains must have at least one label, cannot have
	// a leading empty label, and cannot be longer than 253 characters.
	// if len(s) == 0 || (!constraint && s[0] == '.') || len(s) > 253 {
	// 	return false
	// }

	lastDot := -1
	if constraint && s[0] == '.' {
		s = s[1:]
	}

	for i := 0; i <= len(s); i++ {
		if i < len(s) && (s[i] < 33 || s[i] > 126) {
			// Invalid character.
			return false
		}
		if i == len(s) || s[i] == '.' {
			labelLen := i
			if lastDot >= 0 {
				labelLen -= lastDot + 1
			}
			if labelLen == 0 {
				return false
			}
			// TODO(#75835): labels cannot be longer than 63 characters.
			// if labelLen > 63 {
			// 	return false
			// }
			lastDot = i
		}
	}

	return true
}
