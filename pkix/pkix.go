// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package pkix contains shared, low level structures used for ASN.1 parsing
// and serialization of X.509 certificates, CRL and OCSP.
package pkix

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	asn1 "github.com/pduveau/go-asn1"
)

// AlgorithmIdentifier represents the ASN.1 structure of the same name. See RFC
// 5280, section 4.1.1.2.
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type RDNSequence []RelativeDistinguishedNameSET

var attributeTypeNames = map[string]string{
	"2.5.4.6":  "C",
	"2.5.4.10": "O",
	"2.5.4.11": "OU",
	"2.5.4.3":  "CN",
	"2.5.4.5":  "SERIALNUMBER",
	"2.5.4.7":  "L",
	"2.5.4.8":  "ST",
	"2.5.4.9":  "STREET",
	"2.5.4.17": "POSTALCODE",
}

func typeToExtraNames(v any) (bool, string) {
	switch c := v.(type) {
	case asn1.UTF8String:
		return true, string(c)
	case asn1.IA5String:
		return true, string(c)
	case asn1.NUMERICString:
		return true, string(c)
	case asn1.T61String:
		return true, string(c)
	case string:
		return false, c
	}
	return false, ""
}

func prefixToType(v string) any {
	splitValue := strings.SplitN(v, ":", 2)
	if len(splitValue) == 2 {
		switch splitValue[0] {
		case "utf8":
			return asn1.UTF8String(splitValue[1])
		case "ia5":
			return asn1.IA5String(splitValue[1])
		case "numeric":
			return asn1.NUMERICString(splitValue[1])
		case "t61":
			return asn1.T61String(splitValue[1])
		}
	}
	return v
}

// String returns a string representation of the sequence r,
// roughly following the RFC 2253 Distinguished Names syntax.
func (r RDNSequence) String() string {
	s := ""
	for i := 0; i < len(r); i++ {
		rdn := r[len(r)-1-i]
		if i > 0 {
			s += ","
		}
		for j, tv := range rdn {
			if j > 0 {
				s += "+"
			}

			oidString := tv.Type.String()
			typeName, ok := attributeTypeNames[oidString]
			if !ok {
				derBytes, err := asn1.Marshal(tv.Value)
				if err == nil {
					s += oidString + "=#" + hex.EncodeToString(derBytes)
					continue // No value escaping necessary.
				}

				typeName = oidString
			}

			valueString := fmt.Sprint(tv.Value)
			escaped := make([]rune, 0, len(valueString))

			for k, c := range valueString {
				escape := false

				switch c {
				case ',', '+', '"', '\\', '<', '>', ';':
					escape = true

				case ' ':
					escape = k == 0 || k == len(valueString)-1

				case '#':
					escape = k == 0
				}

				if escape {
					escaped = append(escaped, '\\', c)
				} else {
					escaped = append(escaped, c)
				}
			}

			s += typeName + "=" + string(escaped)
		}
	}

	return s
}

type RelativeDistinguishedNameSET []AttributeTypeAndValue

// AttributeTypeAndValue mirrors the ASN.1 structure of the same name in
// RFC 5280, Section 4.1.2.4.
type AttributeTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value any
}

// AttributeTypeAndValueSET represents a set of ASN.1 sequences of
// [AttributeTypeAndValue] sequences from RFC 2986 (PKCS #10).
type AttributeTypeAndValueSET struct {
	Type  asn1.ObjectIdentifier
	Value [][]AttributeTypeAndValue `asn1:"set"`
}

// Extension represents the ASN.1 structure of the same name. See RFC
// 5280, section 4.2.
type Extension struct {
	Id       asn1.ObjectIdentifier
	Critical bool `asn1:"optional"`
	Value    []byte
}

// Name represents an X.509 distinguished name. This only includes the common
// elements of a DN. Note that Name is only an approximation of the X.509
// structure. If an accurate representation is needed, asn1.Unmarshal the raw
// subject or issuer as an [RDNSequence].
type Name struct {
	Country, Organization, OrganizationalUnit []string
	Locality, Province                        []string
	StreetAddress, PostalCode                 []string
	SerialNumber, CommonName                  string

	// Names contains all parsed attributes. When parsing distinguished names,
	// this can be used to extract non-standard attributes that are not parsed
	// by this package. When marshaling to RDNSequences, the Names field is
	// ignored, see ExtraNames.
	Names []AttributeTypeAndValue

	// ExtraNames contains attributes to be copied, raw, into any marshaled
	// distinguished names. Values override any attributes with the same OID.
	// The ExtraNames field is not populated when parsing, see Names.
	ExtraNames []AttributeTypeAndValue
}

// FillFromRDNSequence populates n from the provided [RDNSequence].
// Multi-entry RDNs are flattened, all entries are added to the
// relevant n fields, and the grouping is not preserved.
func (n *Name) FillFromRDNSequence(rdns *RDNSequence) {
	for _, rdn := range *rdns {
		if len(rdn) == 0 {
			continue
		}

		for _, atv := range rdn {
			extra, value := typeToExtraNames(atv.Value)
			if extra {
				// The type is other than PrintableString then the value is appended in ExtraNames instead of Names
				n.ExtraNames = append(n.ExtraNames, atv)
			} else {
				n.Names = append(n.Names, atv)
			}
			if value == "" {
				continue
			}

			t := atv.Type
			if len(t) == 4 && t[0] == 2 && t[1] == 5 && t[2] == 4 {
				switch t[3] {
				case 3:
					n.CommonName = value
				case 5:
					n.SerialNumber = value
				case 6:
					n.Country = append(n.Country, value)
				case 7:
					n.Locality = append(n.Locality, value)
				case 8:
					n.Province = append(n.Province, value)
				case 9:
					n.StreetAddress = append(n.StreetAddress, value)
				case 10:
					n.Organization = append(n.Organization, value)
				case 11:
					n.OrganizationalUnit = append(n.OrganizationalUnit, value)
				case 17:
					n.PostalCode = append(n.PostalCode, value)
				}
			}
		}
	}
}

var (
	oidCountry            = []int{2, 5, 4, 6}
	oidOrganization       = []int{2, 5, 4, 10}
	oidOrganizationalUnit = []int{2, 5, 4, 11}
	oidCommonName         = []int{2, 5, 4, 3}
	oidSerialNumber       = []int{2, 5, 4, 5}
	oidLocality           = []int{2, 5, 4, 7}
	oidProvince           = []int{2, 5, 4, 8}
	oidStreetAddress      = []int{2, 5, 4, 9}
	oidPostalCode         = []int{2, 5, 4, 17}
)

// appendRDNs appends a relativeDistinguishedNameSET to the given RDNSequence
// and returns the new value. The relativeDistinguishedNameSET contains an
// attributeTypeAndValue for each of the given values. See RFC 5280, A.1, and
// search for AttributeTypeAndValue.
func (n Name) appendRDNs(in RDNSequence, values []string, oid asn1.ObjectIdentifier) RDNSequence {
	if len(values) == 0 || oidInAttributeTypeAndValue(oid, n.ExtraNames) {
		return in
	}

	s := make([]AttributeTypeAndValue, len(values))
	for i, value := range values {
		s[i].Type = oid
		s[i].Value = prefixToType(value)
	}

	return append(in, s)
}

// ToRDNSequence converts n into a single [RDNSequence]. The following
// attributes are encoded as multi-value RDNs:
//
//   - Country
//   - Organization
//   - OrganizationalUnit
//   - Locality
//   - Province
//   - StreetAddress
//   - PostalCode
//
// Each ExtraNames entry is encoded as an individual RDN.
func (n Name) ToRDNSequence() (ret RDNSequence) {
	ret = n.appendRDNs(ret, n.Country, oidCountry)
	ret = n.appendRDNs(ret, n.Province, oidProvince)
	ret = n.appendRDNs(ret, n.Locality, oidLocality)
	ret = n.appendRDNs(ret, n.StreetAddress, oidStreetAddress)
	ret = n.appendRDNs(ret, n.PostalCode, oidPostalCode)
	ret = n.appendRDNs(ret, n.Organization, oidOrganization)
	ret = n.appendRDNs(ret, n.OrganizationalUnit, oidOrganizationalUnit)
	if len(n.CommonName) > 0 {
		ret = n.appendRDNs(ret, []string{n.CommonName}, oidCommonName)
	}
	if len(n.SerialNumber) > 0 {
		ret = n.appendRDNs(ret, []string{n.SerialNumber}, oidSerialNumber)
	}
	for _, atv := range n.ExtraNames {
		ret = append(ret, []AttributeTypeAndValue{atv})
	}

	return ret
}

// String returns the string form of n, roughly following
// the RFC 2253 Distinguished Names syntax.
func (n Name) String() string {
	var rdns RDNSequence
	// If there are no ExtraNames, surface the parsed value (all entries in
	// Names) instead.
	if n.ExtraNames == nil {
		for _, atv := range n.Names {
			t := atv.Type
			if len(t) == 4 && t[0] == 2 && t[1] == 5 && t[2] == 4 {
				switch t[3] {
				case 3, 5, 6, 7, 8, 9, 10, 11, 17:
					// These attributes were already parsed into named fields.
					continue
				}
			}
			// Place non-standard parsed values at the beginning of the sequence
			// so they will be at the end of the string. See Issue 39924.
			rdns = append(rdns, []AttributeTypeAndValue{atv})
		}
	}
	rdns = append(rdns, n.ToRDNSequence()...)
	return rdns.String()
}

// oidInAttributeTypeAndValue reports whether a type with the given OID exists
// in atv.
func oidInAttributeTypeAndValue(oid asn1.ObjectIdentifier, atv []AttributeTypeAndValue) bool {
	for _, a := range atv {
		if a.Type.Equal(oid) {
			return true
		}
	}
	return false
}

// CertificateList represents the ASN.1 structure of the same name. See RFC
// 5280, section 5.1. Use Certificate.CheckCRLSignature to verify the
// signature.
//
// Deprecated: x509.RevocationList should be used instead.
type CertificateList struct {
	TBSCertList        TBSCertificateList
	SignatureAlgorithm AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// HasExpired reports whether certList should have been updated by now.
func (certList *CertificateList) HasExpired(now time.Time) bool {
	return !now.Before(certList.TBSCertList.NextUpdate)
}

// TBSCertificateList represents the ASN.1 structure of the same name. See RFC
// 5280, section 5.1.
//
// Deprecated: x509.RevocationList should be used instead.
type TBSCertificateList struct {
	Raw                 asn1.RawContent
	Version             int `asn1:"optional,default:0"`
	Signature           AlgorithmIdentifier
	Issuer              RDNSequence
	ThisUpdate          time.Time
	NextUpdate          time.Time            `asn1:"optional"`
	RevokedCertificates []RevokedCertificate `asn1:"optional"`
	Extensions          []Extension          `asn1:"tag:0,optional,explicit"`
}

// RevokedCertificate represents the ASN.1 structure of the same name. See RFC
// 5280, section 5.1.
type RevokedCertificate struct {
	SerialNumber   *big.Int
	RevocationTime time.Time
	Extensions     []Extension `asn1:"optional"`
}

type OtherName struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

func (o *OtherName) Set(value any, oid ...int) (err error) {
	if len(oid) < 4 {
		return fmt.Errorf("The oid is invalid !")
	}
	o.Type = asn1.ObjectIdentifier(oid)
	var val []byte
	val, err = asn1.Marshal(value)
	if err == nil {
		o.Value = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: val}
	}
	return
}

// The RegiterID in x509 SAN extension is an alias of asn1.ObjectIdentifier with a different Tag
// Therefore, the methods are wrapped
type RegisterID asn1.ObjectIdentifier

// Equal reports whether oi and other represent the same identifier.
func (rid RegisterID) Equal(other RegisterID) bool {
	return slices.Equal(rid, other)
}

func (rid RegisterID) String() string {
	return asn1.ObjectIdentifier(rid).String()
}

func (rid RegisterID) Marshal() (encoded []byte, err error) {
	var data []byte
	data, err = asn1.Marshal(asn1.ObjectIdentifier(rid))
	if err != nil {
		return
	}
	return data[2:], nil
}

func (rid *RegisterID) Set(value ...int) error {
	if len(value) < 5 {
		return fmt.Errorf("The oid is invalid !")
	}
	*rid = value
	return nil
}

// ReadASN1RegisterID decodes an ASN.1 OBJECT IDENTIFIER into out and
// advances. It reports whether the read was successful.
func (out *RegisterID) ReadASN1(s String) bool {
	oid, err := asn1.ParseObjectIdentifier(s)
	if err != nil {
		return false
	}
	*out = RegisterID(oid)
	return true
}
