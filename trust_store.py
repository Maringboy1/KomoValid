"""
Trust Store and Document Definitions for SignValid.
Contains CCA India Roots, Licensed Certifying Authorities, and Document Signer Profiles.
"""

# Roots operated by the Controller of Certifying Authorities (CCA), Government of India
CCA_ROOTS = [
    {
        "id": "9a3fd317",
        "cn": "CCA India 2022",
        "issuer": "CCA India 2022",
        "kind": "root",
        "valid_from": "2022-02-02",
        "valid_to": "2042-02-02",
        "expired": False,
        "source": "cca.gov.in",
        "operator": "Controller of Certifying Authorities, Government of India"
    },
    {
        "id": "b724689b",
        "cn": "CCA India 2022 SPL",
        "issuer": "CCA India 2022 SPL",
        "kind": "root",
        "valid_from": "2022-09-20",
        "valid_to": "2042-09-20",
        "expired": False,
        "source": "cca.gov.in",
        "operator": "Controller of Certifying Authorities, Government of India"
    },
    {
        "id": "60109bc6",
        "cn": "CCA India 2014",
        "issuer": "CCA India 2014",
        "kind": "root",
        "valid_from": "2014-03-05",
        "valid_to": "2024-03-05",
        "expired": True,
        "source": "cca.gov.in",
        "operator": "Controller of Certifying Authorities, Government of India"
    },
    {
        "id": "c34c5df5",
        "cn": "CCA India 2015 SPL",
        "issuer": "CCA India 2015 SPL",
        "kind": "root",
        "valid_from": "2015-01-29",
        "valid_to": "2025-01-29",
        "expired": True,
        "source": "cca.gov.in",
        "operator": "Controller of Certifying Authorities, Government of India"
    },
    {
        "id": "2d66a702",
        "cn": "CCA India 2011",
        "issuer": "CCA India 2011",
        "kind": "root",
        "valid_from": "2011-03-11",
        "valid_to": "2016-03-11",
        "expired": True,
        "source": "cca.gov.in",
        "operator": "Controller of Certifying Authorities, Government of India"
    },
    {
        "id": "f375e2f7",
        "cn": "CCA India 2007",
        "issuer": "CCA India 2007",
        "kind": "root",
        "valid_from": "2007-06-13",
        "valid_to": "2015-07-04",
        "expired": True,
        "source": "cca.gov.in",
        "operator": "Controller of Certifying Authorities, Government of India"
    },
    {
        "id": "a9d01a3b",
        "cn": "CCA India",
        "issuer": "CCA India",
        "kind": "root",
        "valid_from": "2002-07-05",
        "valid_to": "2009-07-04",
        "expired": True,
        "source": "cca.gov.in",
        "operator": "Controller of Certifying Authorities, Government of India"
    }
]

# Licensed Certifying Authorities & their Sub-CAs
LICENSED_CAS = [
    {
        "name": "(n)Code Solutions",
        "current": 3,
        "expired": 11,
        "certificates": [
            {"id": "5d1d01f0", "cn": "(n)Code Solutions sub-CA for eSign 2024", "issuer": "(n)Code Solutions CA 2022", "kind": "sub-ca", "valid_from": "2024-02-23", "valid_to": "2032-03-14", "expired": False, "source": "cca.gov.in"},
            {"id": "89277300", "cn": "(n)Code Solutions CA 2022", "issuer": "CCA India 2022", "kind": "ca", "valid_from": "2022-03-16", "valid_to": "2032-03-16", "expired": False, "source": "cca.gov.in"},
            {"id": "ea25d9b6", "cn": "(n)Code Solutions Sub-CA for DSC 2022", "issuer": "(n)Code Solutions CA 2022", "kind": "sub-ca", "valid_from": "2022-04-01", "valid_to": "2032-03-14", "expired": False, "source": "cca.gov.in"},
            {"id": "75c6eb3f", "cn": "(n)Code Solutions sub-CA for eSign 2019", "issuer": "(n)Code Solutions CA 2014-1", "kind": "sub-ca", "valid_from": "2019-12-19", "valid_to": "2024-03-04", "expired": True, "source": "cca.gov.in"},
            {"id": "4e95163a", "cn": "(n)Code Solutions CA 2014-1", "issuer": "CCA India 2014", "kind": "ca", "valid_from": "2016-05-12", "valid_to": "2024-03-05", "expired": True, "source": "cca.gov.in"}
        ]
    },
    {
        "name": "e-Mudhra",
        "current": 7,
        "expired": 12,
        "certificates": [
            {"id": "21be69ea", "cn": "e-Mudhra CA 2022", "issuer": "CCA India 2022", "kind": "ca", "valid_from": "2022-02-16", "valid_to": "2032-02-16", "expired": False, "source": "cca.gov.in"},
            {"id": "44bcf86c", "cn": "e-Mudhra CA SPL 2022", "issuer": "CCA India 2022 SPL", "kind": "ca", "valid_from": "2022-11-11", "valid_to": "2032-11-11", "expired": False, "source": "cca.gov.in"},
            {"id": "1d6a6719", "cn": "e-Mudhra Sub CA for Class 2 Document Signer 2022", "issuer": "e-Mudhra CA 2022", "kind": "sub-ca", "valid_from": "2022-02-18", "valid_to": "2032-02-15", "expired": False, "source": "cca.gov.in"},
            {"id": "9a1a8f40", "cn": "e-Mudhra Sub CA for Class 3 Document Signer 2022", "issuer": "e-Mudhra CA 2022", "kind": "sub-ca", "valid_from": "2022-02-18", "valid_to": "2032-02-15", "expired": False, "source": "cca.gov.in"},
            {"id": "b22b7451", "cn": "e-Mudhra Sub CA for Class 3 Individual 2022", "issuer": "e-Mudhra CA 2022", "kind": "sub-ca", "valid_from": "2022-02-18", "valid_to": "2032-02-15", "expired": False, "source": "cca.gov.in"},
            {"id": "8d2fbe7c", "cn": "e-Mudhra Sub CA for eKYC 2022", "issuer": "e-Mudhra CA 2022", "kind": "sub-ca", "valid_from": "2022-02-18", "valid_to": "2032-02-15", "expired": False, "source": "cca.gov.in"},
            {"id": "9e0162cc", "cn": "e-Mudhra CA 2014", "issuer": "CCA India 2014", "kind": "ca", "valid_from": "2014-03-05", "valid_to": "2024-03-05", "expired": True, "source": "cca.gov.in"}
        ]
    },
    {
        "name": "C-DAC",
        "current": 2,
        "expired": 2,
        "certificates": [
            {"id": "70923dd9", "cn": "C-DAC Sub CA for eKYC 2022", "issuer": "C-DAC CA 2022", "kind": "sub-ca", "valid_from": "2024-01-29", "valid_to": "2034-10-25", "expired": False, "source": "cca.gov.in"},
            {"id": "462f390b", "cn": "C-DAC CA 2022", "issuer": "CCA India 2022", "kind": "ca", "valid_from": "2022-06-28", "valid_to": "2032-06-28", "expired": False, "source": "cca.gov.in"}
        ]
    },
    {
        "name": "Capricorn",
        "current": 4,
        "expired": 2,
        "certificates": [
            {"id": "e302c8e2", "cn": "Capricorn CA 2022", "issuer": "CCA India 2022", "kind": "ca", "valid_from": "2022-04-08", "valid_to": "2032-04-08", "expired": False, "source": "cca.gov.in"},
            {"id": "7c1ca69f", "cn": "Capricorn Sub CA for Document Signer DSC 2022", "issuer": "Capricorn CA 2022", "kind": "sub-ca", "valid_from": "2022-04-20", "valid_to": "2032-04-08", "expired": False, "source": "cca.gov.in"},
            {"id": "a9a42f25", "cn": "Capricorn Sub CA for Individual DSC 2022", "issuer": "Capricorn CA 2022", "kind": "sub-ca", "valid_from": "2022-04-20", "valid_to": "2032-04-08", "expired": False, "source": "cca.gov.in"}
        ]
    },
    {
        "name": "Protean eGov (formerly NSDL e-Gov)",
        "current": 1,
        "expired": 3,
        "certificates": [
            {"id": "a9022c0b", "cn": "Protean eGov CA 2022", "issuer": "CCA India 2022", "kind": "ca", "valid_from": "2022-06-28", "valid_to": "2032-06-28", "expired": False, "source": "cca.gov.in"},
            {"id": "bba64c31", "cn": "NSDL e-Gov CA 2014-3", "issuer": "CCA India 2014", "kind": "ca", "valid_from": "2020-09-04", "valid_to": "2024-03-05", "expired": True, "source": "cca.gov.in"}
        ]
    },
    {
        "name": "SafeScrypt",
        "current": 5,
        "expired": 21,
        "certificates": [
            {"id": "66d2c077", "cn": "SafeScrypt CA 2022", "issuer": "CCA India 2022", "kind": "ca", "valid_from": "2022-02-16", "valid_to": "2032-02-16", "expired": False, "source": "cca.gov.in"},
            {"id": "a6b15c49", "cn": "SafeScrypt sub-CA for Document Signer 2022", "issuer": "SafeScrypt CA 2022", "kind": "sub-ca", "valid_from": "2022-02-18", "valid_to": "2032-02-16", "expired": False, "source": "cca.gov.in"},
            {"id": "f51bc972", "cn": "SafeScrypt sub-CA for IncomeTax 2022", "issuer": "SafeScrypt CA 2022", "kind": "sub-ca", "valid_from": "2022-02-24", "valid_to": "2032-02-16", "expired": False, "source": "cca.gov.in"}
        ]
    },
    {
        "name": "NIC (National Informatics Centre)",
        "current": 0,
        "expired": 8,
        "certificates": [
            {"id": "a8e1dfd9", "cn": "NIC CA 2014", "issuer": "CCA India 2014", "kind": "ca", "valid_from": "2014-03-05", "valid_to": "2024-03-05", "expired": True, "source": "cca.gov.in"},
            {"id": "f54ab410", "cn": "NIC sub-CA for NIC 2014", "issuer": "NIC CA 2014", "kind": "sub-ca", "valid_from": "2014-03-06", "valid_to": "2024-03-04", "expired": True, "source": "cca.gov.in"}
        ]
    },
    {
        "name": "SignX",
        "current": 4,
        "expired": 0,
        "certificates": [
            {"id": "a8d6363a", "cn": "SignX CA 2022", "issuer": "CCA India 2022", "kind": "ca", "valid_from": "2022-08-26", "valid_to": "2032-08-26", "expired": False, "source": "cca.gov.in"},
            {"id": "eba4e11f", "cn": "SignX sub-CA for Document Signer 2022", "issuer": "SignX CA 2022", "kind": "sub-ca", "valid_from": "2022-08-30", "valid_to": "2032-08-26", "expired": False, "source": "cca.gov.in"}
        ]
    },
    {
        "name": "Verasys",
        "current": 2,
        "expired": 1,
        "certificates": [
            {"id": "bc2fd40c", "cn": "Verasys CA 2022", "issuer": "CCA India 2022", "kind": "ca", "valid_from": "2022-03-03", "valid_to": "2032-03-03", "expired": False, "source": "cca.gov.in"}
        ]
    },
    {
        "name": "XtraTrust",
        "current": 2,
        "expired": 2,
        "certificates": [
            {"id": "3b6a80da", "cn": "XtraTrust CA 2022", "issuer": "CCA India 2022", "kind": "ca", "valid_from": "2022-03-03", "valid_to": "2032-03-03", "expired": False, "source": "cca.gov.in"}
        ]
    }
]

# Recognised document types and their expected signers
DOCUMENT_TYPES = {
    "aadhaar": {
        "label": "e-Aadhaar",
        "badge": "Central government",
        "expected_signer": "Unique Identification Authority of India",
        "signer_label": "Unique Identification Authority of India (UIDAI)",
        "description": "Signed by the authority this kind of document is issued by — Unique Identification Authority of India (UIDAI).",
        "portal": "myaadhaar.uidai.gov.in",
        "page_slug": "validate-aadhaar-signature"
    },
    "pan": {
        "label": "e-PAN",
        "badge": "Central government",
        "expected_signer": "Income Tax Department / Protean / UTIITSL",
        "signer_label": "Income Tax Department",
        "description": "Signed by the authority this kind of document is issued by — Income Tax Department.",
        "portal": "onlineservices.nsdl.com / pan.utiitsl.com",
        "page_slug": "validate-e-pan-signature"
    },
    "gst": {
        "label": "GST registration certificate",
        "badge": "Central government",
        "expected_signer": "Goods and Services Tax Network",
        "signer_label": "Goods and Services Tax Network (GSTN)",
        "description": "Signed by GST System — Goods and Services Tax Network.",
        "portal": "services.gst.gov.in",
        "page_slug": "validate-gst-certificate-signature"
    },
    "tn_birth": {
        "label": "Tamil Nadu Birth Certificate",
        "badge": "Tamil Nadu e-District",
        "expected_signer": "Commissioner of Municipal Administration / Town Panchayat",
        "signer_label": "Tamil Nadu e-District (e-Sevai)",
        "description": "Signed under the Tamil Nadu e-District / e-Sevai administration hierarchy.",
        "portal": "tnedistrict.tn.gov.in",
        "page_slug": "tn-birth-certificate-signature-validation"
    },
    "tn_income": {
        "label": "Tamil Nadu Income Certificate",
        "badge": "Tamil Nadu e-District",
        "expected_signer": "Tahsildar / Revenue Department",
        "signer_label": "Tamil Nadu Revenue Department",
        "description": "Signed under Tamil Nadu e-District Revenue Administration.",
        "portal": "tnedistrict.tn.gov.in",
        "page_slug": "tn-income-certificate-signature-validation"
    },
    "digilocker": {
        "label": "DigiLocker document",
        "badge": "Central government",
        "expected_signer": "DigiLocker, National e-Governance Division",
        "signer_label": "National e-Governance Division (NeGD)",
        "description": "Signed by DigiLocker repository under Digital India initiative.",
        "portal": "digilocker.gov.in",
        "page_slug": "digilocker-pdf-signature-verify"
    },
    "form16": {
        "label": "Form 16 / TDS Certificate",
        "badge": "Income Tax",
        "expected_signer": "Employer / Tax Deductor",
        "signer_label": "TRACES / Income Tax Department",
        "description": "Generated and signed by authorised employer / tax deductor via TRACES.",
        "portal": "traces.gov.in",
        "page_slug": "validate-form-16-signature"
    },
    "manipur_income": {
        "label": "Manipur e-Services Income Certificate",
        "badge": "Manipur e-District",
        "state_label": "Manipur",
        "expected_signer": "Sub-Divisional Officer (SDO) / Deputy Commissioner (DC), Government of Manipur",
        "signer_label": "Government of Manipur · e-Services Portal",
        "description": "Digitally signed under the Manipur e-District & e-Services administration hierarchy (NIC / CCA India).",
        "portal": "eservicesmanipur.gov.in",
        "page_slug": "manipur-edistrict-certificate-signature-validation"
    },
    "manipur_tribe": {
        "label": "Manipur Scheduled Tribe (ST) Certificate",
        "badge": "Manipur e-District",
        "state_label": "Manipur",
        "expected_signer": "Deputy Commissioner / Sub-Divisional Magistrate (SDM), Manipur",
        "signer_label": "Government of Manipur · Revenue & Tribal Affairs",
        "description": "Official Scheduled Tribe Certificate issued via Manipur eServices / e-District and verified under CCA India.",
        "portal": "eservicesmanipur.gov.in",
        "page_slug": "manipur-edistrict-certificate-signature-validation"
    },
    "manipur_domicile": {
        "label": "Manipur Domicile / Permanent Residence Certificate (PRC)",
        "badge": "Manipur e-District",
        "state_label": "Manipur",
        "expected_signer": "District Administration / DC Office, Government of Manipur",
        "signer_label": "Government of Manipur · District Administration",
        "description": "Permanent Resident Certificate (PRC) / Domicile issued by District Administration via Manipur e-Services.",
        "portal": "eservicesmanipur.gov.in",
        "page_slug": "manipur-edistrict-certificate-signature-validation"
    },
    "manipur_generic": {
        "label": "Manipur e-Services Certificate",
        "badge": "Manipur e-District",
        "state_label": "Manipur",
        "expected_signer": "Authorized Signatory, Government of Manipur",
        "signer_label": "Government of Manipur · e-Services",
        "description": "Digitally signed e-District certificate issued by Government of Manipur under CCA India hierarchy.",
        "portal": "eservicesmanipur.gov.in",
        "page_slug": "manipur-edistrict-certificate-signature-validation"
    },
    "manipur_obc": {
        "label": "Manipur Other Backward Classes (OBC) Certificate",
        "badge": "Manipur e-District",
        "state_label": "Manipur",
        "expected_signer": "Deputy Commissioner / Sub-Divisional Officer (SDO), Manipur",
        "signer_label": "Government of Manipur · Welfare of OBC & SC",
        "description": "Official OBC Certificate issued via Manipur eServices / e-District and verified under CCA India.",
        "portal": "eservicesmanipur.gov.in",
        "page_slug": "manipur-edistrict-certificate-signature-validation"
    },
    "manipur_sc": {
        "label": "Manipur Scheduled Caste (SC) Certificate",
        "badge": "Manipur e-District",
        "state_label": "Manipur",
        "expected_signer": "Deputy Commissioner / Sub-Divisional Officer (SDO), Manipur",
        "signer_label": "Government of Manipur · Revenue & SC Welfare",
        "description": "Official Scheduled Caste Certificate issued via Manipur eServices portal and verified under CCA India.",
        "portal": "eservicesmanipur.gov.in",
        "page_slug": "manipur-edistrict-certificate-signature-validation"
    },
    "manipur_residence": {
        "label": "Manipur Residential Certificate",
        "badge": "Manipur e-District",
        "state_label": "Manipur",
        "expected_signer": "Sub-Divisional Officer (SDO) / SDC, Government of Manipur",
        "signer_label": "Government of Manipur · District Administration",
        "description": "Official Residential Certificate issued via Manipur eServices portal and verified under CCA India.",
        "portal": "eservicesmanipur.gov.in",
        "page_slug": "manipur-edistrict-certificate-signature-validation"
    },
    "manipur_solvency": {
        "label": "Manipur Solvency Certificate",
        "badge": "Manipur e-District",
        "state_label": "Manipur",
        "expected_signer": "Deputy Commissioner, Government of Manipur",
        "signer_label": "Government of Manipur · Revenue Department",
        "description": "Official Solvency Certificate issued via Manipur eServices portal and verified under CCA India.",
        "portal": "eservicesmanipur.gov.in",
        "page_slug": "manipur-edistrict-certificate-signature-validation"
    },
    "generic_signed": {
        "label": "Digitally Signed Document",
        "badge": "Public Key Infrastructure",
        "expected_signer": "Licensed Certificate Authority",
        "signer_label": "Authorized Signatory",
        "description": "Digitally signed with an X.509 PKI certificate under India's IT Act 2000.",
        "portal": "cca.gov.in",
        "page_slug": "validate-digital-signature-pdf"
    }
}
